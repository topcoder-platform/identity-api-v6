/* Signed fixture and HTTP contract checks; no database, events or member mutations. */
require('reflect-metadata');
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { generateKeyPairSync, sign, createHmac } = require('node:crypto');
const nock = require('nock');
const issuer = 'https://identity-keycloak.test/realms/m2m';
Object.assign(process.env, { USE_KEYCLOAK:'true', KEYCLOAK_ISSUER:issuer,
 KEYCLOAK_AUDIENCE:'https://api.test', KEYCLOAK_TOKEN_URL:'https://identity-keycloak.test/m2m/token',
 KEYCLOAK_CLIENT_ID:'identity-test', KEYCLOAK_CLIENT_SECRET:'synthetic-secret', KEYCLOAK_SCOPE:'read:user_profiles write:bus_api',
 AUTH_SECRET:'synthetic-member-secret', VALID_ISSUERS:'["https://member.test"]', AUTH_USER_AUDIENCES:'["member-api"]',
 BUSAPI_URL:'https://bus.test', KAFKA_ERROR_TOPIC:'test.error', MEMBER_API_URL:'https://members.test/members' });
const { publicKey, privateKey } = generateKeyPairSync('rsa',{modulusLength:2048});
/** Sign isolated member/service fixtures; claim overrides exercise rejection boundaries. */
function token(changes={}, member=false) {
 const now=Math.floor(Date.now()/1000);const header=Buffer.from(JSON.stringify(member?{alg:'HS256'}:{alg:'RS256',kid:'identity'})).toString('base64url');
 const claims=member?{iss:'https://member.test',aud:'member-api',userId:123,roles:['administrator'],handle:'fixture'}:{iss:issuer,aud:'https://api.test',sub:'service-identity',azp:'identity-test',gty:'client-credentials',scope:'read:groups'};
 const payload=Buffer.from(JSON.stringify({...claims,iat:now,exp:now+900,...changes})).toString('base64url');const input=header+'.'+payload;
 return input+'.'+(member?createHmac('sha256','synthetic-member-secret').update(input).digest('base64url'):sign('RSA-SHA256',Buffer.from(input),privateKey).toString('base64url'));
}
nock(issuer).persist().get('/protocol/openid-connect/certs').reply(200,{keys:[{...publicKey.export({format:'jwk'}),kid:'identity',alg:'RS256',use:'sig'}]});
const { AuthMiddleware }=require('../dist/auth/auth.middleware');
const middleware=new AuthMiddleware();
/** Execute actual adapter and expose only test principal/status; errors propagate as assertions. */
async function authenticate(value) {
 const req={headers:value===undefined?{}:{authorization:value}};let status=200;let next=false;
 await middleware.use(req,{status(code){status=code;return this},json(){}},()=>{next=true});return {req,status,next};
}
test('shared adapter normalizes members/services and fails closed on invalid credentials',async()=>{
 let result=await authenticate('Bearer '+token());assert.equal(result.req.authUser.kind,'service');assert.equal(result.req.authUser.userId,undefined);assert.equal(result.req.authUser.isAdmin,false);assert.deepEqual(result.req.authUser.roles,[]);
 result=await authenticate('Bearer '+token({scope:'auth0',permissions:['all:user']},true));assert.equal(result.req.user.userId,'123');assert.equal(result.req.user.kind,'user');assert.equal(result.req.user.isAdmin,true);assert.deepEqual(result.req.user.scopes,[]);
 for(const changes of [{aud:'wrong'},{iss:issuer+'/wrong'},{roles:['administrator']},{userId:123},{exp:1},{exp:Math.floor(Date.now()/1000)+1000},{gty:'password'}]) assert.equal((await authenticate('Bearer '+token(changes))).status,401);
 assert.equal((await authenticate('Basic '+token())).status,401);assert.equal((await authenticate()).next,true);
});
test('actual Group routes require explicit read/write service grants over HTTP',async()=>{
 const {Test}=require('@nestjs/testing');const {GroupController}=require('../dist/api/group/group.controller');const {GroupService}=require('../dist/api/group/group.service');
 let reads=0;const module=await Test.createTestingModule({controllers:[GroupController],providers:[{provide:GroupService,useValue:{findMembershipByGroupAndMember:async()=>{reads++;return {id:1}}}}]}).compile();
 const app=module.createNestApplication();app.use(middleware.use.bind(middleware));await app.listen(0,'127.0.0.1');const base=await app.getUrl();
 try {
  let response=await fetch(base+'/groups/1/singleMember/2',{headers:{authorization:'Bearer '+token()}});assert.equal(response.status,200);assert.equal(reads,1);
  for(const scope of ['write:bus_api','READ:groups']) {response=await fetch(base+'/groups/1/singleMember/2',{headers:{authorization:'Bearer '+token({scope})}});assert.equal(response.status,403)}
  response=await fetch(base+'/groups/1/singleMember/2',{headers:{authorization:'Bearer '+token({},true)}});assert.equal(response.status,200);
  response=await fetch(base+'/groups',{method:'POST',headers:{authorization:'Bearer '+token(),'content-type':'application/json'},body:'{}'});assert.equal(response.status,403);
 } finally {await app.close()}
});
test('controller policies reject empty grants, member scopes and cross-operation escalation',async()=>{
 const {UserController}=require('../dist/api/user/user.controller');const controller=Object.create(UserController.prototype);controller.logger={warn(){}};
 const machine=(await authenticate('Bearer '+token({scope:'read:user read:usersRole'}))).req.authUser;
 assert.doesNotThrow(()=>controller.checkAccess(machine,true,['read:user']));assert.throws(()=>controller.checkAccess(machine,true),{status:403});assert.throws(()=>controller.checkResourceIdAndAccess(machine,true,123),{status:403});
 const {ScopesGuard}=require('../dist/auth/guards/scopes.guard');const guard=new ScopesGuard({getAllAndOverride:()=>['auth0']});const member=(await authenticate('Bearer '+token({scope:'auth0'},true))).req.authUser;
 const context={getHandler:()=>null,getClass:()=>null,switchToHttp:()=>({getRequest:()=>({authUser:member})})};assert.throws(()=>guard.canActivate(context),{status:403});
 const {UserRolesController}=require('../dist/api/user-role/user-roles.controller');const roles=Object.create(UserRolesController.prototype);roles.logger={warn(){}};
 assert.doesNotThrow(()=>roles.ensureAdminOrScope(machine,['read:usersRole']));assert.throws(()=>roles.ensureAdminOrScope(machine,['update:usersRole']),{status:403});
 const {hasServiceScopes}=require('../dist/shared/auth/auth.helpers');assert.equal(hasServiceScopes(machine,['read:usersrole']),false);
});
test('authorization-record verification delegates to the same common validator',async()=>{
 const {CommonUtils}=require('../dist/shared/util/common.utils');const principal=await CommonUtils.verifyJwtToken(token(),['https://member.test'],'synthetic-member-secret');assert.equal(principal.kind,'service');assert.equal(principal.userId,undefined);
 await assert.rejects(CommonUtils.verifyJwtToken(token({roles:['admin']}),['https://member.test'],'synthetic-member-secret'));
});
test('Member provider and nested Bus wrapper use verified cached Keycloak credentials',async()=>{
 const {ConfigService}=require('@nestjs/config');const config=new ConfigService(process.env);
 const {MemberApiModule}=require('../dist/shared/member-api/member-api.module');const provider=Reflect.getMetadata('providers',MemberApiModule).find(p=>p.useFactory);const client=provider.useFactory(config);
 const jwt=token({scope:process.env.KEYCLOAK_SCOPE});const original=global.fetch;let count=0;global.fetch=async(url,options)=>{assert.equal(url,process.env.KEYCLOAK_TOKEN_URL);assert.equal(JSON.parse(options.body).client_id,'identity-test');count++;return new Response(JSON.stringify({access_token:jwt,token_type:'Bearer',expires_in:900}),{status:200})};
 try {assert.equal(await client.getMachineToken(),jwt);assert.equal(await client.getMachineToken(),jwt);assert.equal(count,1);
 const {EventModule}=require('../dist/shared/event/event.module');const busProvider=Reflect.getMetadata('providers',EventModule).find(p=>p.useFactory);const bus=busProvider.useFactory(config);
 const mock=nock('https://bus.test',{reqheaders:{authorization:'Bearer '+jwt}}).post('/bus/events').twice().reply(200,{});
 const event={topic:'test.topic',originator:'identity-test',timestamp:new Date().toISOString(), 'mime-type':'application/json',payload:{}};
 await bus.postEvent(event);await bus.postEvent(event);assert(mock.isDone());assert.equal(count,2);
 } finally {global.fetch=original}
});
