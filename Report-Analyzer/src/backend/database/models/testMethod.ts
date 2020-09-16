import { Schema } from 'mongoose';


export interface ITestMethod {
  Description: string,
  SecuritySeverity: string,
  InteroperabilitySeverity: string,
  TlsVersion: string,
  RFC: {
    Section: string,
    number: number
  }
  MethodName: string,
  DisplayName: string,
  ClassName: string
}

export const TestMethodSchemaObject = {
  Description: String,
  SecuritySeverity: String,
  InteroperabilitySeverity: String,
  TlsVersion: String,
  RFC: {
    Section: String,
    number: Number
  },
  MethodName: String,
  DisplayName: String,
  ClassName: String
}

