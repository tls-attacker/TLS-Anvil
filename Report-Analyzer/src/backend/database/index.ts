import mongoose, { Schema } from "mongoose"
import { TestResultContainerSchema, ITestResultContainer, ITestResult, TestResultSchema, IState, StateSchema } from './models';
import { BadRequest } from '../errors';
import { promises } from 'fs';

class Database {
  testResultContainer = mongoose.model<ITestResultContainer>("TestContainer", TestResultContainerSchema)
  private testResult = mongoose.model<ITestResult>("TestResult", TestResultSchema)
  private testResultState = mongoose.model<IState>("TestResultState", StateSchema)

  constructor() {
    console.log("DB object created")
  }

  connect(): Promise<void> {
    return new Promise((res, rej) => {
      mongoose.connect('mongodb://localhost:27017/reportAnalyzer', { useNewUrlParser: true, useUnifiedTopology: true }).then(() => {
        res()
      }).catch((e) => {
        rej(e)
      })
    })
  }

  async resultContainerExistsForIdentifier(identifier: string): Promise<ITestResultContainer> {
    return this.testResultContainer.findOne({Identifier: identifier}).exec()
  }

  removeResultContainer(identifier: string) {
    this.testResultContainer.findOne({Identifier: identifier}).then((doc) => {
      this.testResult.deleteMany({ ContainerId: doc._id })
      this.testResultState.deleteMany({ ContainerId: doc._id })
      doc.deleteOne()
    })
  }

  async addResultContainer(container: ITestResultContainer): Promise<void> {
    const containerDoc = new this.testResultContainer(container)
    const testResultDocs: ITestResult[] = []
    const stateDocs: IState[] = []
    
    for (let i = 0; i < container.TestResults.length; i++) {
      const result = container.TestResults[i]
      result.ContainerId = containerDoc._id
      const testResultDoc = new this.testResult(result)
      const stateIds = []
      const uuids: string[] = []
      for (let state of result.States) {
        state.TestResultId = testResultDoc._id
        state.ContainerId = containerDoc._id
        const stateDoc = new this.testResultState(state)
        stateIds.push(stateDoc._id)
        if (uuids.includes(stateDoc.uuid)) {
          throw new BadRequest(`uuid of state is not unique: ${stateDoc.uuid} (${result.TestMethod.ClassName}.${result.TestMethod.MethodName})`)
        }
        uuids.push(stateDoc.uuid)
        testResultDoc.StateIndexMap.set(stateDoc.uuid, stateIds.length - 1)
        stateDocs.push(stateDoc)
      }

      testResultDoc.States = stateIds
      testResultDocs.push(testResultDoc)
      containerDoc.TestResultClassMethodIndexMap.set(`${testResultDoc.TestMethod.ClassName}.${testResultDoc.TestMethod.MethodName}`.replace(/\./g, "||"), i)
    }

    containerDoc.TestResults = testResultDocs.map(i => i._id)

    const promises: Promise<any>[] = []
    promises.push(containerDoc.save())
    promises.push(this.testResult.insertMany(testResultDocs))
    promises.push(this.testResultState.insertMany(stateDocs))
    return Promise.all(promises).then(() => {
      return
    })
  }

  async getResultContainer(identifier: string): Promise<Pick<ITestResultContainer, any>> {
    return this.testResultContainer.findOne({ Identifier: identifier }).populate({path: 'TestResults', populate: {path: 'States'}}).lean().exec()
  }

  async getTestResult(identifier: string, className: string, methodName: string): Promise<Pick<ITestResult, any>> {
    const container = await this.testResultContainer.findOne({ Identifier: identifier }).exec()
    return this.testResult.findOne({
      ContainerId: container._id, 
      'TestMethod.ClassName': className, 
      'TestMethod.MethodName': methodName
    }).populate('States').lean().exec()
  }

}

const _db = new Database()
export default _db


