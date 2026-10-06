export type SupportedLocale = 'en' | 'es' | 'fr';

export interface TranslationSet {
  magicLink: { subject: string; heading: string; body: (ttlMinutes: number) => string; cta: string; footer: string };
  passwordReset: { subject: string; heading: string; body: string; cta: string; footer: string };
  invitation: { subject: string; heading: string; body: (expiresOn: string) => string; cta: string };
  webhookDeadLetter: {
    subject: (eventType: string) => string;
    heading: string;
    body: (url: string, eventType: string, attempts: number) => string;
    lastError: string;
    footer: string;
  };
}

/**
 * Minimal, dependency-free i18n: a typed translation table per locale.
 * Real projects with heavier localization needs would swap this for
 * i18next/FormatJS without changing EmailService's public API — the
 * `t()` lookup below is the only integration point.
 */
const translations: Record<SupportedLocale, TranslationSet> = {
  en: {
    magicLink: {
      subject: 'Your sign-in link',
      heading: 'Sign in',
      body: (ttl) => `Click the button below to sign in. This link expires in ${ttl} minutes and can only be used once.`,
      cta: 'Sign in',
      footer: "If you didn't request this, you can safely ignore this email.",
    },
    passwordReset: {
      subject: 'Reset your password',
      heading: 'Reset your password',
      body: 'Click the button below to choose a new password. This link expires in 1 hour.',
      cta: 'Reset password',
      footer: "If you didn't request this, you can safely ignore this email.",
    },
    invitation: {
      subject: "You've been invited",
      heading: "You're invited",
      body: (expiresOn) => `You've been invited to join a workspace. This invitation expires on ${expiresOn}.`,
      cta: 'Accept invitation',
    },
    webhookDeadLetter: {
      subject: (eventType) => `Webhook delivery failing: ${eventType}`,
      heading: 'A webhook endpoint has stopped receiving events',
      body: (url, eventType, attempts) =>
        `Your endpoint <code>${url}</code> failed to accept the <strong>${eventType}</strong> event after ${attempts} attempts and has been marked dead-lettered.`,
      lastError: 'Last error',
      footer: "Check your endpoint's health, then re-send from the delivery log if needed.",
    },
  },
  es: {
    magicLink: {
      subject: 'Tu enlace de acceso',
      heading: 'Iniciar sesión',
      body: (ttl) => `Haz clic en el botón para iniciar sesión. Este enlace caduca en ${ttl} minutos y solo puede usarse una vez.`,
      cta: 'Iniciar sesión',
      footer: 'Si no solicitaste esto, puedes ignorar este correo de forma segura.',
    },
    passwordReset: {
      subject: 'Restablece tu contraseña',
      heading: 'Restablece tu contraseña',
      body: 'Haz clic en el botón para elegir una nueva contraseña. Este enlace caduca en 1 hora.',
      cta: 'Restablecer contraseña',
      footer: 'Si no solicitaste esto, puedes ignorar este correo de forma segura.',
    },
    invitation: {
      subject: 'Has sido invitado/a',
      heading: 'Estás invitado/a',
      body: (expiresOn) => `Has sido invitado/a a unirte a un espacio de trabajo. Esta invitación caduca el ${expiresOn}.`,
      cta: 'Aceptar invitación',
    },
    webhookDeadLetter: {
      subject: (eventType) => `Fallo en la entrega del webhook: ${eventType}`,
      heading: 'Un endpoint de webhook ha dejado de recibir eventos',
      body: (url, eventType, attempts) =>
        `Tu endpoint <code>${url}</code> no aceptó el evento <strong>${eventType}</strong> tras ${attempts} intentos y se marcó como fallido definitivo.`,
      lastError: 'Último error',
      footer: 'Revisa el estado de tu endpoint y reenvía desde el registro de entregas si es necesario.',
    },
  },
  fr: {
    magicLink: {
      subject: 'Votre lien de connexion',
      heading: 'Connexion',
      body: (ttl) => `Cliquez sur le bouton ci-dessous pour vous connecter. Ce lien expire dans ${ttl} minutes et ne peut être utilisé qu'une seule fois.`,
      cta: 'Se connecter',
      footer: "Si vous n'êtes pas à l'origine de cette demande, ignorez simplement cet e-mail.",
    },
    passwordReset: {
      subject: 'Réinitialisez votre mot de passe',
      heading: 'Réinitialisez votre mot de passe',
      body: 'Cliquez sur le bouton ci-dessous pour choisir un nouveau mot de passe. Ce lien expire dans 1 heure.',
      cta: 'Réinitialiser le mot de passe',
      footer: "Si vous n'êtes pas à l'origine de cette demande, ignorez simplement cet e-mail.",
    },
    invitation: {
      subject: 'Vous avez été invité(e)',
      heading: 'Vous êtes invité(e)',
      body: (expiresOn) => `Vous avez été invité(e) à rejoindre un espace de travail. Cette invitation expire le ${expiresOn}.`,
      cta: "Accepter l'invitation",
    },
    webhookDeadLetter: {
      subject: (eventType) => `Échec de livraison du webhook : ${eventType}`,
      heading: 'Un point de terminaison webhook a cessé de recevoir des événements',
      body: (url, eventType, attempts) =>
        `Votre point de terminaison <code>${url}</code> n'a pas accepté l'événement <strong>${eventType}</strong> après ${attempts} tentatives et a été marqué comme définitivement échoué.`,
      lastError: 'Dernière erreur',
      footer: "Vérifiez l'état de votre point de terminaison, puis renvoyez depuis le journal des livraisons si nécessaire.",
    },
  },
};

export function t(locale: string | undefined, defaultLocale: string): TranslationSet {
  const key = (locale || defaultLocale) as SupportedLocale;
  return translations[key] || translations[defaultLocale as SupportedLocale] || translations.en;
}
