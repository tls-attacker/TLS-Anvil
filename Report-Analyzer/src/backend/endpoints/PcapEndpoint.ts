import { spawnSync } from 'child_process'
import { ITestResultContainer, IState } from '../database/models'
import fs, { promises as fsPromises } from 'fs';
import moment from 'moment';
import { NextFunction, Request, Response, Router } from 'express';
import DB, { FileType } from '../database';



export namespace PcapEndpoint {
  export class Controller {
    private router: Router

    constructor(aRouter: Router) {
      this.router = aRouter

      this.router.get("/testReport/:containerId/testResult/:className/:methodName/:uuid/pcap", this.getPcap.bind(this))
    }


    private async getPcap(req: Request, res: Response, next: NextFunction) {
      const containerId = req.params.containerId
      const className = req.params.className
      const methodName = req.params.methodName
      const uuid = req.params.uuid
    
      const container = await DB.testResultContainer.findOne({_id: containerId}).exec()
      await this.downloadFiles(container)
      const doc = await DB.getTestResult(container.Identifier, className, methodName)
    
      let startTimestamp: moment.Moment = moment()
      let state: IState
    
      const index = (<any>doc.StateIndexMap)[uuid]
      state = doc.States[index]
      startTimestamp = moment(new Date(state.StartTimestamp))
      startTimestamp.local()
    
      await this.execProgram(null, 'tcpdump', [
        '-r', '/tmp/p' + container.PcapStorageId, 
        '-w', `/tmp/filtered_${state._id}.pcap`, 
        `tcp port ${state.SrcPort} and tcp port ${state.DstPort}`
      ])
    
    
      const timeFilter = `frame.time >= "${startTimestamp.subtract(1, 'seconds').format("YYYY-MM-DD HH:mm:ss.S")}"` +
                        `&& frame.time <= "${startTimestamp.add(10, 'seconds').format("YYYY-MM-DD HH:mm:ss.S")}"`
    
      let output : any;  
      if (req.query.download) {
        output = await this.execProgram(null, 
          'tshark', 
          [
            '-r', `/tmp/filtered_${state._id}.pcap`, '-w', '-',
            '-2', '-R', timeFilter
          ]
        )
      } else {
        output = await this.execProgram(null, 
          'tshark', 
          [
            '-n', '-r', `/tmp/filtered_${state._id}.pcap`,
            '-d', `tcp.port==${state.DstPort},tls`,
            '-d', `tcp.port==${state.SrcPort},tls`,
            '-o', `tls.keylog_file:/tmp/k${container.KeylogfileStorageId}`, '-Y', timeFilter,
            '-o', 'gui.column.format:"Time","%Aut","s","%uS","d","%uD","Protocol","%p","Info","%i"',
            '-T', 'tabs'
          ]
        )
      }
    
      if (req.query.download) {
        res.type('application/octet-stream')
        res.send(output)
        return
      }
      res.setHeader('Content-Type', "text/plain")
      res.send(output.toString('utf-8').trim().split('\n').map((i: string) => `<div class="${this.classForPacket(i)}">${i.trim()}</div>`).join(''))
    
    }


    private async downloadFiles(container: ITestResultContainer): Promise<void> {
      if (fs.existsSync('/tmp/k' + container.KeylogfileStorageId)
          && fs.existsSync('/tmp/p' + container.PcapStorageId)) {
        return
      }
    
      const pcap = DB.downloadFile(FileType.pcap, container.PcapStorageId)
      const keylog = DB.downloadFile(FileType.keylog, container.KeylogfileStorageId)
    
      const vals = await Promise.all([pcap, keylog])
      const pcapFile = vals[0];
      const keylogFile = vals[1];
    
      const promises = []
      promises.push(fsPromises.writeFile('/tmp/k' + container.KeylogfileStorageId, keylogFile))
      promises.push(fsPromises.writeFile('/tmp/p' + container.PcapStorageId, pcapFile))
    
      return Promise.all(promises).then(() => {
        return;
      })
    }

    private async execProgram(stdin: Buffer, program: string, args: string[]): Promise<Buffer> {
      const env = {...process.env}
      env.COLORTERM="24bit"
      env.TERM="xterm-256color"
      env.COLORFGBG="7;0"
      env.LSCOLORS="Gxfxcxdxbxegedabagacad"
      env.ITERM_PROFILE="Default"
      env.LC_TERMINAL="iTerm2"
    
      return new Promise((res) => {
        const ret = spawnSync(program, args, {
          input: stdin || 'pipe',
          env: env,
        })
        console.error(ret.stderr.toString('utf-8'))
        res(ret.stdout)
      })
    }

    private classForPacket(packet: string) {
      let css = {
        bgColor: '',
        fgColor: 'black',
        type: 'packet'
      }
    
      if (["SYN", "FIN"].filter(j => packet.includes(j)).length > 0)
        css.bgColor = 'gray'
      if (packet.includes("HTTP"))
        css.bgColor = "green"
      if (packet.includes("TLS"))
        css.bgColor = 'blue'
      if (packet.includes("RST")) {
        css.bgColor = 'red'
        css.fgColor = 'yellow'
      }
      
      return ['bg-' + css.bgColor, 'fg-' + css.fgColor, css.type].join(' ')
    }
    
  }
}












