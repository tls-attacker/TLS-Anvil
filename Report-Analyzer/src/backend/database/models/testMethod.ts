import { Schema } from 'mongoose';
import { IScoreMap, ScoreMapSchmaObject, ScoreSchemaObject } from './score';


export interface ITestMethod {
  Description: string,
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
  TlsVersion: String,
  RFC: {
    Section: String,
    number: Number
  },
  MethodName: String,
  DisplayName: String,
  ClassName: String
}

