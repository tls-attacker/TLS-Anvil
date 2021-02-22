package uploader

import (
	"encoding/json"
	"fmt"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"log"
	"strings"
	"sync"
	"time"
	"uploader/src/database"
	"uploader/src/database/models"
)

type UploadData struct {
	JsonRaw []byte
	Keylog []byte
	Pcap []byte

	Container *models.Container
	Results []models.Result
	States []models.State

	Identifier string

	Finished chan bool
	uploader *uploader
}

var uploadQueue = make(chan *UploadData)

func init() {
	go scheduleUpload()
}

type Uploader interface {
	Upload(data *UploadData)
}

func NewUploader(size int) Uploader {
	u := new(uploader)
	u.database = database.NewDatabase()
	u.size = size

	return u
}

type uploader struct {
	database database.Database
	size int
	finished int
}

func (u *uploader) Upload(data *UploadData) {
	data.uploader = u

	if u.database.ReportExists(data.Identifier) {
		u.finished = u.finished + 1
		log.Printf("%03d/%03d Skipped %s (exists already)\n", u.finished, u.size, data.Identifier)
		return
	}

	if err := u.preprocess(data); err != nil {
		u.finished = u.finished + 1
		log.Printf("%03d/%03d Error while preprocessing %s, %s\n", u.finished, u.size, data.Identifier, err)
		return
	}

	if data.Finished == nil {
		data.Finished = make(chan bool)
	}

	uploadQueue <- data
	<- data.Finished

}

func (u *uploader) preprocess(data *UploadData) error {
	var container models.Container
	if err := json.Unmarshal(data.JsonRaw, &container); err != nil {
		return err
	}

	data.JsonRaw = nil
	container.Date = time.Unix(0, int64(container.DateInt) * int64(time.Millisecond))

	container.Flatten()

	data.States = make([]models.State, 0)
	data.Results = container.TestResultsStructs
	container.ID = primitive.NewObjectID()
	container.Identifier = data.Identifier
	container.ShortIdentifier = data.Identifier[:len(data.Identifier)-6]
	container.TestResultClassMethodIndexMap = make(map[string]int)

	testResultIds := make([]primitive.ObjectID, 0)

	for i, _ := range data.Results {
		testResult := &data.Results[i]
		testResult.ContainerId = container.ID
		testResult.ID = primitive.NewObjectID()
		testResult.StateIndexMap = make(map[string]int)
		uuids := make(map[string]bool)
		uuidsAreUnique := true

		stateIds := make([]primitive.ObjectID, 0)
		states := testResult.StatesStructs

		for j, _ := range states {
			s := &states[j]
			s.ID = primitive.NewObjectID()
			s.ContainerId = container.ID
			s.TestResultId = testResult.ID
			if !uuidsAreUnique {
				continue
			} else if _, ok := uuids[s.Uuid]; ok {
				uuidsAreUnique = false
				log.Printf("uuids are not unique %s %s", testResult.TestMethod.ClassName + "." + testResult.TestMethod.MethodName, data.Identifier)
				continue
			}

			uuids[s.Uuid] = true

			stateIds = append(stateIds, s.ID)
			data.States = append(data.States, *s)
			testResult.StateIndexMap[s.Uuid] = len(stateIds) - 1
		}

		if !uuidsAreUnique {
			testResult.Result = "PARSER_ERROR"
		}

		testResult.States = stateIds
		testResultIds = append(testResultIds, testResult.ID)
		method := fmt.Sprintf("%s.%s", testResult.TestMethod.ClassName, testResult.TestMethod.MethodName)
		method = strings.ReplaceAll(method, ".", "||")
		container.TestResultClassMethodIndexMap[method] = i
	}

	container.TestResults = testResultIds

	data.Container = &container

	return nil
}


func upload(data *UploadData) {
	t := time.Now()
	data.Container.KeylogfileStorageId = primitive.NewObjectID()
	data.Container.PcapStorageId = primitive.NewObjectID()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		data.uploader.database.UploadFile(database.Keylog, data.Identifier, data.Container.KeylogfileStorageId, data.Keylog)
		data.Keylog = nil
		wg.Done()
	}()

	go func() {
		data.uploader.database.UploadFile(database.Pcap, data.Identifier, data.Container.PcapStorageId, data.Pcap)
		data.Pcap = nil
		wg.Done()
	}()

	data.uploader.database.AddContainer(*data.Container)
	data.uploader.database.AddResults(data.Results)
	data.uploader.database.AddStates(data.States)

	wg.Wait()
	data.uploader.finished = data.uploader.finished + 1
	log.Printf("%03d/%03d Uploaded %s (%s)\n", data.uploader.finished, data.uploader.size, data.Container.Identifier, time.Since(t))
	data.Finished <- true
}

func scheduleUpload() {
	for data := range uploadQueue {
		upload(data)

		if data.uploader.size == data.uploader.finished {
			break
		}
	}

	log.Printf("Finished uploading!")
}



