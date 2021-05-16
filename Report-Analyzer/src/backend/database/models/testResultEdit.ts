import { Document, ObjectId, Schema } from 'mongoose';
import { CategoriesStrings, EditMode, Optional, TestResult } from '../../../lib/const';
import { ITimestamp } from './timestamps';



export interface ITestResultEdit {
  Results: Optional<ObjectId[]>,
  Containers: Optional<ObjectId[]>,
  description: string,
  title: string,
  editMode: EditMode,
  newResult: TestResult,
  MethodName: string,
  ClassName: string,
}

export interface ITestResultEditDocument extends ITestResultEdit, Document, ITimestamp {

}

export const TestResultEditSchema = new Schema({
  Results: [{
    type: Schema.Types.ObjectId,
    ref: 'TestResult',
  }],
  Containers: [{
    type: Schema.Types.ObjectId,
    ref: 'TestContainer',
  }],
  title: String,
  description: String,
  editMode: String,
  newResult: String,
  MethodName: String,
  ClassName: String
}, {
  timestamps: true
})

TestResultEditSchema.index({"Containers": 1, "ClassName": 1, "MethodName": 1})
TestResultEditSchema.index({"Results": 1, "ClassName": 1, "MethodName": 1})
TestResultEditSchema.index({"ClassName": 1, "MethodName": 1})
