export interface BrandConfig {
  productName: string;
  logoUrl?: string;
  primaryColor: string;
  supportEmail?: string;
}

/**
 * A single shared HTML shell so every transactional email (magic link,
 * password reset, invitation, webhook alert) looks consistent and
 * carries the operator's branding — configured once via BRAND_NAME /
 * BRAND_LOGO_URL / BRAND_PRIMARY_COLOR / BRAND_SUPPORT_EMAIL rather than
 * hand-styled per template.
 */
export function renderBrandedEmail(
  brand: BrandConfig,
  opts: {
    heading: string;
    bodyHtml: string;
    ctaLabel?: string;
    ctaUrl?: string;
    footerHtml?: string;
    preheader?: string;
  },
): string {
  const logo = brand.logoUrl
    ? `<img src="${brand.logoUrl}" alt="${escapeHtml(brand.productName)}" style="height:32px;margin-bottom:24px;" />`
    : `<div style="font-size:18px;font-weight:700;color:${brand.primaryColor};margin-bottom:24px;">${escapeHtml(brand.productName)}</div>`;

  const cta =
    opts.ctaLabel && opts.ctaUrl
      ? `<p style="margin:28px 0;">
           <a href="${opts.ctaUrl}" style="background:${brand.primaryColor};color:#ffffff;text-decoration:none;padding:12px 28px;border-radius:8px;display:inline-block;font-weight:600;font-size:15px;">${escapeHtml(opts.ctaLabel)}</a>
         </p>
         <p style="color:#9ca3af;font-size:12px;word-break:break-all;">${opts.ctaUrl}</p>`
      : '';

  const support = brand.supportEmail
    ? `<p style="color:#9ca3af;font-size:12px;">Need help? Contact <a href="mailto:${brand.supportEmail}" style="color:${brand.primaryColor};">${brand.supportEmail}</a></p>`
    : '';

  return `<!DOCTYPE html>
<html>
  <body style="margin:0;padding:0;background:#f9fafb;">
    ${opts.preheader ? `<span style="display:none;max-height:0;overflow:hidden;">${escapeHtml(opts.preheader)}</span>` : ''}
    <div style="font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;max-width:480px;margin:0 auto;padding:40px 24px;">
      ${logo}
      <h2 style="margin:0 0 16px;color:#111827;font-size:20px;">${escapeHtml(opts.heading)}</h2>
      <div style="color:#374151;line-height:1.6;font-size:15px;">${opts.bodyHtml}</div>
      ${cta}
      ${opts.footerHtml ? `<p style="color:#9ca3af;font-size:13px;margin-top:24px;">${opts.footerHtml}</p>` : ''}
      ${support}
    </div>
  </body>
</html>`;
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
