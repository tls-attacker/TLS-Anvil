package models

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
	"time"
)

type Container struct {
	ID                            primitive.ObjectID   `bson:"_id"`
	PcapStorageId                 primitive.ObjectID   `bson:"PcapStorageId"`
	KeylogfileStorageId           primitive.ObjectID   `bson:"KeylogfileStorageId"`
	Identifier                    string               `bson:"Identifier"`
	ShortIdentifier               string               `bson:"ShortIdentifier"`
	DateInt                       int                  `bson:"-" json:"Date"`
	Date                          time.Time            `bson:"Date" json:"-"`
	DisplayName                   string               `bson:"DisplayName"`
	ElapsedTime                   int                  `bson:"ElapsedTime"`
	FailedTests                   int                  `bson:"FailedTests"`
	SucceededTests                int                  `bson:"SucceededTests"`
	DisabledTests                 int                  `bson:"DisabledTests"`
	TestResultClassMethodIndexMap map[string]int       `bson:"TestResultClassMethodIndexMap"`
	StatesCount                   int                  `bson:"StatesCount"`
	Score                         map[string]Score     `bson:"Score"`
	TestResults                   []primitive.ObjectID `bson:"TestResults"  json:"-"`
	TestResultsStructs            []Result             `bson:"-"            json:"TestResults"`
	TestClasses                   []Container          `bson:"-"            json:"TestClasses"`
	CreatedAt                     time.Time            `bson:"createdAt"`
	UpdatedAt                     time.Time            `bson:"updatedAt"`
}

func (c *Container) getResults() []Result {
	results := make([]Result, 0)

	if c.TestResultsStructs != nil {
		results = append(results, c.TestResultsStructs...)
	}

	containers := c.TestClasses
	if containers != nil {
		for _, v := range containers {
			results = append(results, v.getResults()...)
		}
	}

	return results
}

func (c *Container) Flatten() {
	results := c.getResults()
	c.TestResultsStructs = results
	c.TestClasses = nil
}
