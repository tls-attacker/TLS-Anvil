import mongodb from 'mongodb';
import mongoose, { ObjectId } from "mongoose";
import { Readable } from 'stream';
import { IState, ITestResult, ITestResultContainer, ITestResultEditDocument, StateSchema, TestResultContainerSchema, TestResultEditSchema, TestResultSchema } from './models';
import { BadRequest } from '../errors';
import { CategoriesStrings, TestResult } from '../../lib/const';
import { calculateScoreDelta, IScoreDeltaMap } from './models/score';

export enum FileType {
  pcap,
  keylog
}
class Database {
  testResultContainer = mongoose.model<ITestResultContainer>("TestContainer", TestResultContainerSchema)
  testResultEdit = mongoose.model<ITestResultEditDocument>("TestResultEdit", TestResultEditSchema)
  testResult = mongoose.model<ITestResult>("TestResult", TestResultSchema)
  private testResultState = mongoose.model<IState>("TestResultState", StateSchema)
  private rawDb: mongodb.Db;
  private pcapBucket: mongodb.GridFSBucket
  private keylogfileBucket: mongodb.GridFSBucket

  private rawDb_testResults: mongodb.Collection

  constructor() {
    console.log("DB object created")
  }

  connect(): Promise<void> {
    return new Promise((res, rej) => {
      let conHost = 'localhost'
      if (process.env.PRODUCTION) {
        conHost = 'mongo'
      }
      mongoose.connect(`mongodb://${conHost}:27017/reportAnalyzer`, { useNewUrlParser: true, useUnifiedTopology: true }).then((m) => {
        this.rawDb = m.connection.db
        this.rawDb_testResults = this.rawDb.collection("testresults")
        this.pcapBucket = new mongodb.GridFSBucket(this.rawDb, {
          bucketName: "pcap"
        })
        this.keylogfileBucket = new mongodb.GridFSBucket(this.rawDb, {
          bucketName: "keylogfile"
        })
        res()
      }).catch((e) => {
        rej(e)
      })
    })
  }

  async resultContainerExistsForIdentifier(identifier: string): Promise<ITestResultContainer> {
    return this.testResultContainer.findOne({Identifier: identifier}).exec()
  }

  async removeResultContainer(identifier: string): Promise<any> {
    const doc = await this.testResultContainer.findOne({ Identifier: identifier });
    if (!doc) {
      throw new BadRequest("Invalid identifier")
    }
    
    this.testResult.deleteMany({ ContainerId: doc._id }).exec();
    this.testResultState.deleteMany({ ContainerId: doc._id }).exec();
    this.pcapBucket.delete(doc.PcapStorageId);
    this.keylogfileBucket.delete(doc.KeylogfileStorageId);
    doc.deleteOne();
  }

  async addResultContainer(container: ITestResultContainer, pcap: string, keylogfile: string): Promise<void> {
    const containerDoc = new this.testResultContainer(container)
    const testResultDocs: ITestResult[] = []
    const stateDocs: IState[] = []
    
    // console.time("prepareAdd")
    for (let i = 0; i < container.TestResults.length; i++) {
      const result = container.TestResults[i]
      result.ContainerId = containerDoc._id
      const testResultDoc = new this.testResult(result)
      const stateIds = []
      const uuids: string[] = []
      let uuidsAreUnique = true
      for (let state of result.States) {
        if (uuids.includes(state.uuid)) {
          uuidsAreUnique = false
          console.warn(`uuids are not unique (${result.TestMethod.ClassName}.${result.TestMethod.MethodName}) ${state.uuid}`)
          continue
        }
        state.TestResultId = testResultDoc._id
        state.ContainerId = containerDoc._id
        const stateDoc = new this.testResultState(state)
        stateIds.push(stateDoc._id)
        uuids.push(stateDoc.uuid)
        //@ts-ignore
        testResultDoc.StateIndexMap.set(stateDoc.uuid, stateIds.length - 1)
        stateDocs.push(stateDoc)
      }

      if (!uuidsAreUnique) {
        testResultDoc.Result = "PARSER_ERROR"
      }

      testResultDoc.States = stateIds
      testResultDocs.push(testResultDoc)
      //@ts-ignore
      containerDoc.TestResultClassMethodIndexMap.set(`${testResultDoc.TestMethod.ClassName}.${testResultDoc.TestMethod.MethodName}`.replace(/\./g, "||"), i)
    }
    // console.timeEnd("prepareAdd")

    containerDoc.TestResults = testResultDocs.map(i => i._id)

    const promises: Promise<any>[] = []
    // console.time("uploadFiles")
    promises.push(this.uploadFile(FileType.pcap, pcap, containerDoc.Identifier))
    promises.push(this.uploadFile(FileType.keylog, keylogfile, containerDoc.Identifier))

    return Promise.all(promises).then((vals) => { 
      // console.timeEnd("uploadFiles")
      containerDoc.PcapStorageId = vals[0]
      containerDoc.KeylogfileStorageId = vals[1]
      const promises2: Promise<any>[] = []

      // console.time("triggerSaves")
      // console.time("saveTime")
      promises2.push(containerDoc.save())
      for (let result of testResultDocs) {
        promises2.push(result.save())
      }

      for (let state of stateDocs) {
        promises2.push(state.save())
      }
      // console.timeEnd("triggerSaves")

      return Promise.all(promises2)
    }).then(() => {
      // console.timeEnd("saveTime")
      return
    }).catch((e) => {
      console.log(e)
      console.log(e.stack)
      throw e
    })
  }

  async getResultContainer(identifier: string): Promise<Pick<ITestResultContainer, any>> {
    console.time("query container " + identifier)
    const container = await this.testResultContainer.findOne({ Identifier: identifier }).lean().exec() // populate({path: 'TestResults'}).lean().exec()
    console.timeEnd("query container " + identifier)

    const p = this.testResult.find({ContainerId: container._id.toString()}).lean().exec()

    const edits = this.testResultEdit.find({
      "$or": [
        {Containers: {"$in": [container._id.toString()]}},
        {Containers: null},
      ]
    }).sort({"createdAt": "asc"}).lean().exec()

    let resultScoreDelta: IScoreDeltaMap = {}

    console.time("query results " + identifier)
    container.TestResults = await p
    console.timeEnd("query results " + identifier)
    for (let edit of (await edits)) {
      const methodName = `${edit.ClassName}.${edit.MethodName}`.replace(/\./g, "||")
      const resultIndex = container.TestResultClassMethodIndexMap[methodName]
      const result = container.TestResults[resultIndex]

      const scoreDelta = calculateScoreDelta(result.Score, edit.newResult)
      resultScoreDelta = {...resultScoreDelta, ...scoreDelta}

      result.Result = edit.newResult
      result.edited = true
      result.appliedEdit = <any>edit
      result.matchingEdits = <any>edits
    }
    

    for (const key of Object.keys(resultScoreDelta)) {
      const v = resultScoreDelta[<CategoriesStrings>key]
      const score = container.Score[<CategoriesStrings>key]
      score.Reached += v.ReachedDelta
      score.Total   += v.TotalDelta
      score.Percentage = (score.Reached / score.Total * 100)
    }

    return container
  }

  async getTestResult(identifier: string, className: string, methodName: string): Promise<Pick<ITestResult, any>> {
    const container = await this.testResultContainer.findOne({ Identifier: identifier }).select({_id: 1}).lean().exec()
    const result = await this.testResult.findOne({
      ContainerId: container._id.toString(), 
      'TestMethod.ClassName': className, 
      'TestMethod.MethodName': methodName
    }).populate('States').lean().exec()

    if (!result || result.Result === TestResult.DISABLED) {
      return result
    }

    const edits = await this.testResultEdit.find({
      "$or": [
        {Containers: {"$in": [container._id.toString()]}},
        {Containers: null},
      ],
      MethodName: methodName,
      ClassName: className
    }).sort({createdAt: 'desc'}).lean().exec()

    if (edits.length > 1) {
      console.warn(`Multiple edits were found targeting ${className.replace("de.rub.nds.tlstest.suite.tests.", "")}.${methodName}@${identifier}`)
      console.warn("Only evaluating the newest one")
    }

    if (edits.length > 0) {
      result.Result = edits[0].newResult
      result.edited = true
      result.appliedEdit = <any>edits[0]
      result.matchingEdits = <any>edits

      // updates result.Score inplace
      calculateScoreDelta(result.Score, edits[0].newResult)
    }

    return result
  }


  async getTestResults(identifiers: string[], className: string, methodName: string): Promise<Pick<ITestResult, any>[]> {
    const promises = []
    for (const identifier of identifiers) {
      const p = this.getTestResult(identifier, className, methodName)
      promises.push(p)
    }

    return Promise.all(promises)
  }

  async uploadFile(filetype: FileType, data: string, filename: string): Promise<mongoose.Types.ObjectId> {
    return new Promise((res, rej) => {
      const buf = Buffer.from(data, 'base64')
      const readableStream = new Readable()
      readableStream.push(buf)
      readableStream.push(null)

      let uploadStream;
      if (filetype == FileType.pcap)
        uploadStream = this.pcapBucket.openUploadStream(filename);
      else if (filetype == FileType.keylog)
        uploadStream = this.keylogfileBucket.openUploadStream(filename);

      const id = uploadStream.id
      readableStream.pipe(uploadStream)
      uploadStream.on('error', (e) => {
        console.error('onerror' ,e)
        rej(e)
      })

      uploadStream.on('finish', () => {
        res(new mongoose.Types.ObjectId(id.toString()))
      })
    })
  }

  async downloadFile(fileType: FileType, id: mongoose.Types.ObjectId): Promise<Buffer> {
    return new Promise((res, rej) => {
      let downloadStream;
      if (fileType == FileType.pcap)
        downloadStream = this.pcapBucket.openDownloadStream(id)
      else if (fileType == FileType.keylog)
        downloadStream = this.keylogfileBucket.openDownloadStream(id)

      const out: any[] = []
      downloadStream.on('data', (chunk) => {
        out.push(chunk)
      })

      downloadStream.on('error', (e) => {
        rej(e)
      })

      downloadStream.on('end', () => {
        res(Buffer.concat(out))
      })
    })
  }

  async downloadKeylogFiles(identifiers: string[]): Promise<Buffer> {
    const containers = await this.testResultContainer.find({Identifier: {$in: identifiers}}).lean().exec()
    const promises = []
    for (let doc of containers) {
      promises.push(this.downloadFile(FileType.keylog, doc.KeylogfileStorageId))
    }

    return Promise.all(promises).then((values) => {
      return Buffer.concat(values)
    })
  }
}

const _db = new Database()
export default _db


