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
    // identity api uses limit/offset but expose page links for convenience
    params.set('limit', String(perPage))
    params.set('offset', String(Math.max(0, (p - 1) * perPage)))
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

  res.set('X-Page', String(page))
  res.set('X-Per-Page', String(perPage))
  res.set('X-Total', String(total))
  res.set('X-Total-Pages', String(totalPages))
  res.set('Link', links.join(', '))
  res.set(
    'Access-Control-Expose-Headers',
    'X-Page, X-Per-Page, X-Total, X-Total-Pages, Link',
  )
}

