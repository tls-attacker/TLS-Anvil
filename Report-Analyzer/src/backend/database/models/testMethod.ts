import { Schema } from 'mongoose';
import { IScoreMap, ScoreMapSchmaObject, ScoreSchemaObject } from './score';


export interface ITestMethod {
  Description: string,
  TestDescription: string,
  TlsVersion: string,
  RFC: {
    Section: string,
    Number: number
  }
  MethodName: string,
  DisplayName: string,
  ClassName: string
}

export const TestMethodSchemaObject = {
  Description: String,
  TestDescription: String,
  TlsVersion: String,
  RFC: {
    Section: String,
    Number: Number
  },
  MethodName: String,
  DisplayName: String,
  ClassName: String
}

