import { Response, Request } from 'express'
import { URL } from 'url'

export function setPaginationHeaders(
  res: Response,
  req: Request,
  total: number,
  page: number,
  perPage: number,
) {
  const totalPages = Math.max(1, Math.ceil(total / Math.max(1, perPage)))

  const baseUrl = `${req.protocol}://${req.get('host')}`
  const url = new URL(req.originalUrl || req.url, baseUrl)

  const getPageLink = (p: number) => {
    const params = new URLSearchParams(url.search)
    // If the incoming request uses page/perPage, keep that style. Otherwise, use limit/offset.
    const usesPage = params.has('page') || params.has('perPage')
    if (usesPage) {
      params.set('perPage', String(perPage))
      params.set('page', String(Math.max(1, p)))
    } else {
      params.set('limit', String(perPage))
      params.set('offset', String(Math.max(0, (p - 1) * perPage)))
    }
    return `${url.pathname}?${params.toString()}`
  }

  const links: string[] = []
  if (page < totalPages) {
    links.push(`<${getPageLink(page + 1)}>; rel="next"`)
  }
  if (page > 1) {
    links.push(`<${getPageLink(page - 1)}>; rel="prev"`)
  }
  links.push(`<${getPageLink(totalPages)}>; rel="last"`)
  links.push(`<${getPageLink(1)}>; rel="first"`)

  if (page > 1) {
    res.set('X-Prev-Page', String(page - 1))
  }
  if (page < totalPages) {
    res.set('X-Next-Page', String(page + 1))
  }
  res.set('X-Page', String(page))
  res.set('X-Per-Page', String(perPage))
  res.set('X-Total', String(total))
  res.set('X-Total-Pages', String(totalPages))
  res.set('Link', links.join(', '))
  let expose = (res.getHeader('Access-Control-Expose-Headers') as string) || ''
  expose += expose ? ', ' : ''
  expose += 'X-Page, X-Per-Page, X-Total, X-Total-Pages, X-Prev-Page, X-Next-Page, Link'
  res.set('Access-Control-Expose-Headers', expose)
}
