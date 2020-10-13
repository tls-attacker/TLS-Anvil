import mongodb from 'mongodb';
import mongoose from "mongoose";
import { Readable } from 'stream';
import { IState, ITestResult, ITestResultContainer, StateSchema, TestResultContainerSchema, TestResultSchema } from './models';
import { BadRequest } from '../errors';
import { TestStatus, SeverityLevel, SeverityLevelStrings, score } from '../../lib/const'

export enum FileType {
  pcap,
  keylog
}
class Database {
  testResultContainer = mongoose.model<ITestResultContainer>("TestContainer", TestResultContainerSchema)
  private testResult = mongoose.model<ITestResult>("TestResult", TestResultSchema)
  private testResultState = mongoose.model<IState>("TestResultState", StateSchema)
  private rawDb: mongodb.Db;
  private pcapBucket: mongodb.GridFSBucket
  private keylogfileBucket: mongodb.GridFSBucket

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
    
    for (let i = 0; i < container.TestResults.length; i++) {
      const result = container.TestResults[i]
      result.ContainerId = containerDoc._id
      const testResultDoc = new this.testResult(result)
      const stateIds = []
      const uuids: string[] = []
      let uuidsAreUnique = true
      for (let state of result.States) {
        state.TestResultId = testResultDoc._id
        state.ContainerId = containerDoc._id
        const stateDoc = new this.testResultState(state)
        stateIds.push(stateDoc._id)
        if (uuids.includes(stateDoc.uuid)) {
          uuidsAreUnique = false
          console.warn(`uuids are not unique (${result.TestMethod.ClassName}.${result.TestMethod.MethodName})`)
          continue
        }
        uuids.push(stateDoc.uuid)
        testResultDoc.StateIndexMap.set(stateDoc.uuid, stateIds.length - 1)
        stateDocs.push(stateDoc)
      }

      if (!uuidsAreUnique) {
        testResultDoc.Status = "PARSER_ERROR"
      }

      testResultDoc.States = stateIds
      testResultDocs.push(testResultDoc)
      containerDoc.TestResultClassMethodIndexMap.set(`${testResultDoc.TestMethod.ClassName}.${testResultDoc.TestMethod.MethodName}`.replace(/\./g, "||"), i)
    }

    containerDoc.TestResults = testResultDocs.map(i => i._id)

    const promises: Promise<any>[] = []
    promises.push(this.uploadFile(FileType.pcap, pcap, containerDoc.Identifier))
    promises.push(this.uploadFile(FileType.keylog, keylogfile, containerDoc.Identifier))

    return Promise.all(promises).then((vals) => { 
      containerDoc.PcapStorageId = vals[0]
      containerDoc.KeylogfileStorageId = vals[1]
      promises.push(containerDoc.save())
      promises.push(this.testResult.insertMany(testResultDocs))
      promises.push(this.testResultState.insertMany(stateDocs))
      return Promise.all(promises)
    }).then(() => {
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


