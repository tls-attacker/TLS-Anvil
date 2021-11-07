package uploader

import (
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
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
	JsonFile             string
	KeylogFile           string
	PcapFile             string
	ContainerResultFiles []string

	Summary    *models.Summary

	uploader *uploader
	Logger *logrus.Entry
	Mutex sync.RWMutex
	UploadStart time.Time
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

func ParseJson(filePath string, target interface{}) error {
	f, _ := os.Open(filePath)
	defer f.Close()

	decoder := json.NewDecoder(f)
	if err := decoder.Decode(target); err != nil {
		return err
	}

	return nil
}

func (u *uploader) Upload(data *UploadData) {
	data.uploader = u
	data.Logger = Logger.WithField("identifier", data.Summary.Identifier)

	//if u.database.ReportExists(data.Summary.Identifier) {
	//	u.finished = u.finished + 1
	//	data.Logger.Infof("%03d/%03d Skipped (exists already)", u.finished, u.size)
	//	return
	//}

	if err := u.preprocess(data); err != nil {
		u.finished = u.finished + 1
		data.Logger.Errorf("%03d/%03d Error while preprocessing, %s", u.finished, u.size, err)
		return
	}

	data.UploadStart = time.Now()
	uploadFiles(data)
}


func (u *uploader) preprocessResult(filepath string, data *UploadData, index int) (primitive.ObjectID, error) {
	var testResult models.Result
	if err := ParseJson(filepath, &testResult); err != nil {
		data.Logger.Errorf("Error parsing JSON %s %v", filepath, err)
		return primitive.ObjectID{}, errors.Errorf("Error parsing JSON %s %v", filepath, err)
	}

	testResult.ContainerId = data.Summary.ID
	testResult.ID = primitive.NewObjectID()
	testResult.StateIndexMap = make(map[string]int)
	uuids := make(map[string]bool)
	uuidsAreUnique := true

	stateIds := make([]primitive.ObjectID, 0)
	states := make([]models.State, 0)
	stateStructs := testResult.StatesStructs

	for j, _ := range stateStructs {
		s := stateStructs[j]
		s.ID = primitive.NewObjectID()
		s.ContainerId = data.Summary.ID
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
		states = append(states, s)
		testResult.StateIndexMap[s.Uuid] = len(stateIds) - 1
	}

	if !uuidsAreUnique {
		testResult.Result = "PARSER_ERROR"
	}

	testResult.States = stateIds

	method := fmt.Sprintf("%s.%s", testResult.TestMethod.ClassName, testResult.TestMethod.MethodName)
	method = strings.ReplaceAll(method, ".", "||")

	data.Mutex.Lock()
	data.Summary.TestResultClassMethodIndexMap[method] = index
	data.Mutex.Unlock()

	if len(states) > 0 {
		u.database.AddStates(states)
	}

	u.database.AddResult(testResult)

	return testResult.ID, nil
}

func (u *uploader) preprocess(data *UploadData) error {
	container := data.Summary

	data.Logger.Debug("Start prerocessing")
	container.Date = time.Unix(0, int64(container.DateInt) * int64(time.Millisecond))

	container.ID = primitive.NewObjectID()
	container.ShortIdentifier = container.Identifier[:len(container.Identifier)-6]
	container.TestResultClassMethodIndexMap = make(map[string]int)

	testResultIds := make([]primitive.ObjectID, len(data.ContainerResultFiles))

	var wg sync.WaitGroup
	wg.Add(len(data.ContainerResultFiles))
	data.Mutex = sync.RWMutex{}

	for i, containerResultFilePath := range data.ContainerResultFiles {
		go func(j int, containerResultFilePath string) {
			testResultId, err := u.preprocessResult(containerResultFilePath, data, j)

			if err == nil {
				testResultIds[j] = testResultId
				wg.Done()
			}
		}(i, containerResultFilePath)
	}

	wg.Wait()

	container.TestResults = testResultIds

	data.Logger.Debug("Finished preprocessing")

	return nil
}


func uploadFiles(data *UploadData) {
	data.Summary.KeylogfileStorageId = primitive.NewObjectID()
	data.Summary.PcapStorageId = primitive.NewObjectID()

	var wg sync.WaitGroup
	wg.Add(2)
	data.Logger.Trace("Starting upload")

	go func() {
		f, _ := os.Open(data.KeylogFile)
		data.uploader.database.UploadFile(database.Keylog, data.Summary.Identifier, data.Summary.KeylogfileStorageId, f)
		f.Close()
		data.Logger.Trace("Finished uploading keylogfile")
		wg.Done()
	}()

	go func() {
		f, _ := os.Open(data.PcapFile)
		data.uploader.database.UploadFile(database.Pcap, data.Summary.Identifier, data.Summary.PcapStorageId, f)
		f.Close()
		data.Logger.Trace("Finished uploading pcap")
		wg.Done()
	}()

	data.uploader.database.AddContainer(*data.Summary)

	wg.Wait()
	data.uploader.finished = data.uploader.finished + 1
	data.Logger.Infof("%03d/%03d Upload finished (%s)", data.uploader.finished, data.uploader.size, time.Since(data.UploadStart))
}
