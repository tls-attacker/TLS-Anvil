import { Schema, Document } from "mongoose";
import { ITimestamp } from './timestamps';
import { ITestResult } from './testResult';

export interface ITestResultContainer extends Document, ITimestamp {
  Identifier: string,
  DisplayName: string
  ElapsedTime: number,
  FailedTests: number,
  SucceededTests: number,
  DisabledTests: number,
  TestClasses?: ITestResultContainer[]
  TestResults: ITestResult[]
  TestResultClassMethodIndexMap: Map<string, number>
}


export const TestResultContainerSchema = new Schema({
  Identifier: {
    type: String,
    required: true,
  },
  DispalyName: String,
  ElapsedTime: Number,
  FailedTests: Number,
  SucceededTests: Number,
  DisabledTests: Number,
  TestResults: [{
    type: Schema.Types.ObjectId,
    ref: 'TestResult'
  }],
  TestResultClassMethodIndexMap: {
    type: Schema.Types.Map,
    of: Number,
    default: new Map()
  }
}, {
  timestamps: true
})

TestResultContainerSchema.index({Identifier: 1})
