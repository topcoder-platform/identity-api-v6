import {
  Inject,
  Injectable,
  Logger,
  OnModuleDestroy,
  OnModuleInit,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaClient } from '@prisma/client';
import { Constants } from '../../core/constant/constants';
import { MemberStatus } from '../../dto/member/member.status.enum';
import { EventService } from '../../shared/event/event.service';
import { PRISMA_CLIENT } from '../../shared/prisma/prisma.module';
import { CommonUtils } from '../../shared/util/common.utils';
import { ACTIVATION_MODE } from './activation-code';

@Injectable()
export class ActivationEmailWorker implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(ActivationEmailWorker.name);
  private timer?: NodeJS.Timeout;
  private running = false;

  constructor(
    @Inject(PRISMA_CLIENT) private readonly prisma: PrismaClient,
    private readonly config: ConfigService,
    private readonly events: EventService,
  ) {}

  onModuleInit() {
    this.timer = setInterval(() => void this.dispatch(), 5000);
    this.timer.unref();
  }

  onModuleDestroy() {
    clearInterval(this.timer);
  }

  async dispatch() {
    if (this.running) return;
    this.running = true;
    try {
      const pending = await this.prisma.user_otp_email.findMany({
        where: { mode: ACTIVATION_MODE, delivery_due_at: { lte: new Date() } },
        select: { id: true, expire_at: true, delivery_due_at: true },
        orderBy: { delivery_due_at: 'asc' },
        take: 25,
      });
      await Promise.all(
        pending.map((job) =>
          this.deliver(job.id, job.expire_at, job.delivery_due_at),
        ),
      );
    } catch {
      this.logger.error('Could not poll pending activation emails.');
    } finally {
      this.running = false;
    }
  }

  private async deliver(id: number, generationExpiry: Date, dueAt: Date) {
    // An abandoned claim becomes eligible again. A late acknowledgement can
    // only clear its own lease, even if the member requested another code.
    const lease = new Date(Date.now() + 60000);
    try {
      const claimed = await this.prisma.user_otp_email.updateMany({
        where: { id, expire_at: generationExpiry, delivery_due_at: dueAt },
        data: { delivery_due_at: lease },
      });
      if (!claimed.count) return;
      const job = await this.prisma.user_otp_email.findFirst({
        where: {
          id,
          delivery_due_at: lease,
          expire_at: { equals: generationExpiry, gt: new Date() },
          user: { status: MemberStatus.UNVERIFIED },
        },
        select: {
          otp: true,
          delivery_recipient: true,
          user: {
            select: {
              handle: true,
              emails: {
                where: {
                  primary_ind: Constants.primaryEmailFlag,
                  email_type_id: Constants.standardEmailType,
                },
                select: { address: true },
              },
            },
          },
        },
      });
      if (
        job?.delivery_recipient &&
        job.user.emails.some(
          (email) => email.address === job.delivery_recipient,
        )
      ) {
        const template = this.config.getOrThrow<string>(
          'SENDGRID_RESEND_ACTIVATION_EMAIL_TEMPLATE_ID',
        );
        if (!template) throw new Error('Missing activation email template');
        await this.events.postDirectBusMessage('external.action.email', {
          data: { handle: job.user.handle, code: job.otp },
          from: {
            email: `Topcoder <noreply@${CommonUtils.getAppDomain(this.config)}>`,
          },
          version: 'v3',
          sendgrid_template_id: template,
          recipients: [job.delivery_recipient],
        });
      }
      await this.prisma.user_otp_email.updateMany({
        where: { id, expire_at: generationExpiry, delivery_due_at: lease },
        data: { delivery_due_at: null },
      });
    } catch {
      this.logger.error(
        `Activation email job ${id} will retry after its lease expires.`,
      );
    }
  }
}
