export enum ScoreCategories {
  SECURITY = "SECURITY",
  INTEROPERABILITY = "INTEROPERABILITY",
  COMPLIANCE = "COMPLIANCE"
}

export type CategoriesStrings = keyof typeof ScoreCategories

export const allScoreCategories = [
  ScoreCategories.SECURITY,
  ScoreCategories.INTEROPERABILITY,
  ScoreCategories.COMPLIANCE
];