package main

import (
	"io/ioutil"
	"log"
	_ "net/http/pprof"
	"os"
	"path"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	uploader "uploader/src"
	"uploader/src/config"
)

var workers chan int

func readFile(p string, target *[]byte) error {
	c, err := ioutil.ReadFile(p)
	if err != nil {
		log.Println("Error while reading file ", p)
		return err
	}

	*target = c

	return nil
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	//go func() {
	//	http.ListenAndServe("localhost:6060", nil)
	//}()

	conf := config.GetConfig()
	workers = make(chan int, conf.PreprocessingThreads)

	for i := 1; i <= conf.PreprocessingThreads; i++ {
		workers <- i
	}

	fpath := conf.BasePath
	var err error
	fpath, err = filepath.Abs(fpath)
	if err != nil {
		log.Fatalln(err)
	}

	var stat os.FileInfo
	stat, err = os.Stat(fpath)
	if err != nil {
		log.Fatalln(err)
	} else if !stat.IsDir() {
		fpath = filepath.Dir(fpath)
	}

	files := make([]string, 0)
	filepath.Walk(fpath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Fatalln(err)
		}

		if strings.Contains(path, "/testResults.json") {
			files = append(files, path)
		}

		return nil
	})

	wg := sync.WaitGroup{}
	u := uploader.NewUploader(len(files))
	for _, v := range files {
		workerId := <- workers

		dir := path.Dir(v)
		uploadData := &uploader.UploadData{}

		if err = readFile(v, &uploadData.JsonRaw); err != nil {
			continue
		}

		if err = readFile(filepath.Join(dir, "keyfile.log"), &uploadData.Keylog); err != nil {
			continue
		}

		if err = readFile(filepath.Join(dir, "dump.pcap"), &uploadData.Pcap); err != nil {
			continue
		}

		uploadData.Identifier = path.Base(dir)

		wg.Add(1)
		go func(data *uploader.UploadData, group *sync.WaitGroup, worker int) {
			u.Upload(data)
			debug.FreeOSMemory()
			group.Done()
			workers <- worker
		}(uploadData, &wg, workerId)

	}

	wg.Wait()

	//select {
	//
	//}

}
