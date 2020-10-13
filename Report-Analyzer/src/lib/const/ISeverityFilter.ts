import { SeverityLevelStrings } from './SeverityLevel';

export interface ISeverityFilter {
  security: SeverityLevelStrings[];
  interoperability: SeverityLevelStrings[];
  compliance: SeverityLevelStrings[];
}
