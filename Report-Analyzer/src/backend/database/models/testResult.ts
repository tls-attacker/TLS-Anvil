import { IState, StateSchema } from "./state";
import { ITestMethod, TestMethodSchemaObject } from "./testMethod";
import { Schema, Document } from 'mongoose';
import { ITestResultContainer } from './testResultContainer';

export interface ITestResult extends Document {
  ContainerId: ITestResultContainer['_id'],
  TestMethod: ITestMethod,
  Status: string,
  DisabledReason?: string,
  FailedReason?: string,
  FailedStacktrace?: string,
  ElapsedTime: number,
  States: IState[],
  StateIndexMap: Map<string, number>
}

export const TestResultSchema = new Schema({
  ContainerId: {
    type: Schema.Types.ObjectId,
    ref: 'TestContainer',
    required: true
  },
  TestMethod: TestMethodSchemaObject,
  Status: String,
  DisabledReason: String,
  FailedReason: String,
  FailedStacktrace: String,
  ElapsedTime: Number,
  States: [{
    type: Schema.Types.ObjectId,
    ref: 'TestResultState',
  }],
  StateIndexMap: {
    type: Schema.Types.Map,
    of: Number,
    default: new Map()
  }
})

TestResultSchema.index({ContainerId: 1})
TestResultSchema.index({Status: 1})
