
import { TestReportService } from '../services'
import { expose } from 'threads/worker'
import DB from '../database'
import { ITestResultContainer } from '../database/models'


async function uploader(json: ITestResultContainer, pcapDump: string, keylog: string): Promise<void> {
  await DB.connect()
  
  const testReportService = new TestReportService(json)
  const formattedReport = testReportService.prepareTestReport()
  
  return DB.addResultContainer(formattedReport, pcapDump, keylog)
}

export type Uploader = typeof uploader

expose(uploader)
