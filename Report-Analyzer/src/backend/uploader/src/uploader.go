package uploader

import (
	"encoding/json"
	"fmt"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"os"
	"strings"
	"sync"
	"time"
	"uploader/src/database"
	"uploader/src/database/models"
	. "uploader/src/logging"
)

type UploadData struct {
	JsonFile   *os.File
	KeylogFile *os.File
	PcapFile   *os.File

	Container *models.Container
	Results []models.Result
	States []models.State

	Identifier string

	Finished chan bool
	uploader *uploader
	Logger *logrus.Entry
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
	data.Logger = Logger.WithField("identifier", data.Identifier)

	if u.database.ReportExists(data.Identifier) {
		u.finished = u.finished + 1
		data.Logger.Infof("%03d/%03d Skipped (exists already)", u.finished, u.size)
		return
	}

	if err := u.preprocess(data); err != nil {
		u.finished = u.finished + 1
		data.Logger.Errorf("%03d/%03d Error while preprocessing, %s", u.finished, u.size, err)
		return
	}

	if data.Finished == nil {
		data.Finished = make(chan bool)
	}

	uploadQueue <- data
	<- data.Finished
}

func (u *uploader) preprocess(data *UploadData) error {
	//container := models.Container{}
	var container models.Container

	data.Logger.Debug("Start prerocessing")
	decoder := json.NewDecoder(data.JsonFile)
	if err := decoder.Decode(&container); err != nil {
		return err
	}
	data.JsonFile.Close()
	data.Logger.Traceln("Finished parsing")

	container.Date = time.Unix(0, int64(container.DateInt) * int64(time.Millisecond))

	container.Flatten()

	data.Logger.Traceln("Flattened results")

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
				data.Logger.Warningf("uuids are not unique %s", testResult.TestMethod.ClassName + "." + testResult.TestMethod.MethodName)
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

	data.Logger.Debug("Finished preprocessing")

	return nil
}


func upload(data *UploadData) {
	t := time.Now()
	data.Container.KeylogfileStorageId = primitive.NewObjectID()
	data.Container.PcapStorageId = primitive.NewObjectID()

	var wg sync.WaitGroup
	wg.Add(2)
	data.Logger.Trace("Starting upload")

	go func() {
		data.uploader.database.UploadFile(database.Keylog, data.Identifier, data.Container.KeylogfileStorageId, data.KeylogFile)
		data.KeylogFile.Close()
		data.Logger.Trace("Finished uploading keylogfile")
		wg.Done()
	}()

	go func() {
		data.uploader.database.UploadFile(database.Pcap, data.Identifier, data.Container.PcapStorageId, data.PcapFile)
		data.PcapFile.Close()
		data.Logger.Trace("Finished uploading pcap")
		wg.Done()
	}()

	data.uploader.database.AddContainer(*data.Container)
	data.uploader.database.AddResults(data.Results)
	data.uploader.database.AddStates(data.States)

	wg.Wait()
	data.uploader.finished = data.uploader.finished + 1
	data.Logger.Infof("%03d/%03d Upload finished (%s)", data.uploader.finished, data.uploader.size, time.Since(t))
	data.Finished <- true
}

func scheduleUpload() {
	for data := range uploadQueue {
		upload(data)

		if data.uploader.size == data.uploader.finished {
			break
		}
	}

	Logger.Infoln("Finished uploading!")
}



