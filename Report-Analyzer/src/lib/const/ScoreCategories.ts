export enum ScoreCategories {
  ALERT = "ALERT",
  CVE = "CVE",
  CERTIFICATE = "CERTIFICATE",
  CRYPTO = "CRYPTO",
  DEPRECATED = "DEPRECATED",
  HANDSHAKE = "HANDSHAKE",
  MESSAGESTRUCTURE = "MESSAGESTRUCTURE",
  RECORDLAYER = "RECORDLAYER",
  SECURITY = "SECURITY",
  INTEROPERABILITY = "INTEROPERABILITY",
  COMPLIANCE = "COMPLIANCE"
}

export type CategoriesStrings = keyof typeof ScoreCategories

export const allScoreCategories = [
  ScoreCategories.ALERT,
  ScoreCategories.CVE,
  ScoreCategories.CERTIFICATE,
  ScoreCategories.CRYPTO,
  ScoreCategories.DEPRECATED,
  ScoreCategories.HANDSHAKE,
  ScoreCategories.MESSAGESTRUCTURE,
  ScoreCategories.RECORDLAYER,
  ScoreCategories.SECURITY,
  ScoreCategories.INTEROPERABILITY,
  ScoreCategories.COMPLIANCE
];
