import { Router } from 'express';
import DB, { FileType } from '../database';


export namespace KeylogFileEndpoint {
  export class Controller {
    private router: Router
  
    constructor(aRouter: Router) {
      this.router = aRouter
      this.init();
    }
  
    private init() {
      this.router.get('/keylogfile', (req, res, next) => {
        res.type('application/octet-stream')
        const identifiers: string = typeof req.query.identifiers == 'string' ? req.query.identifiers : ""
        DB.downloadKeylogFiles(identifiers.split(',')).then((buf) => {
          res.setHeader("Content-Disposition", 'attachment; filename="keylogfile.log"')
          res.send(buf)
        })
      })
    }
  }
}




