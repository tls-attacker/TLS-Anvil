package database

import (
	"context"
	"fmt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/gridfs"
	"go.mongodb.org/mongo-driver/mongo/options"
	"os"
	"time"
	"uploader/src/config"
	"uploader/src/database/models"
	. "uploader/src/logging"
)

type BucketName int

const (
	Keylog BucketName = 1
	Pcap BucketName = 2
)

type Database interface {
	AddContainer(document models.Container)
	AddResults(documents []models.Result)
	AddStates(documents []models.State)
	Insert(col string, doc interface{})
	InsertMany(col string, doc []interface{})
	UploadFile(bucket BucketName, filename string, id primitive.ObjectID, file *os.File)
	ReportExists(identifier string) bool
}

func NewDatabase() Database {
	db := &database{}

	connectionOpts := options.Client()
	connectionOpts.ApplyURI(fmt.Sprintf("mongodb://%s/reportanalyzer", config.GetConfig().DatabaseUrl))

	var err error
	db.client, err = mongo.NewClient(connectionOpts)
	if err != nil {
		Logger.Fatal(err)
	}
	db.context, _ = context.WithCancel(context.Background())
	err = db.client.Connect(db.context)
	if err != nil {
		Logger.Fatal(err)
	}

	q, _ := context.WithTimeout(db.context, 5 * time.Second)
	if err := db.client.Ping(q, nil); err != nil {
		Logger.Fatal("Could not connect to database: ", err)
	}

	db.database = db.client.Database("reportAnalyzer")
	db.collections = newCollections(db.database)

	opts := options.GridFSBucket()
	opts.SetName("keylogfile")
	db.bucketKeylog, _ = gridfs.NewBucket(db.database, opts)

	opts = options.GridFSBucket()
	opts.SetName("pcap")
	db.bucketPcap, _ = gridfs.NewBucket(db.database, opts)

	return db
}


type database struct {
	client *mongo.Client
	context context.Context
	collections *collections
	database *mongo.Database

	bucketKeylog *gridfs.Bucket
	bucketPcap *gridfs.Bucket
}

func (d *database) AddResults(results []models.Result) {
	documents := make([]interface{}, len(results))
	for i, _ := range results {
		results[i].UpdatedAt = time.Now()
		results[i].CreatedAt = time.Now()
		documents[i] = results[i]
	}
	if _, err := d.collections.results.InsertMany(d.context, documents); err != nil {
		Logger.Error(err)
	}
}

func (d *database) AddStates(states []models.State) {
	documents := make([]interface{}, len(states))
	for i, _ := range states {
		states[i].UpdatedAt = time.Now()
		states[i].CreatedAt = time.Now()
		documents[i] = states[i]
	}
	if _, err := d.collections.states.InsertMany(d.context, documents); err != nil {
		Logger.Error(err)
	}
}

func (d *database) AddContainer(document models.Container) {
	document.CreatedAt = time.Now()
	document.UpdatedAt = time.Now()
	if _, err := d.collections.containers.InsertOne(d.context, document); err != nil {
		Logger.Error(err)
	}
}

func (d *database) Insert(col string, doc interface{}) {
	if _, err := d.database.Collection(col).InsertOne(d.context, doc); err != nil {
		Logger.Error(err)
	}
}

func (d *database) InsertMany(col string, docs []interface{}) {
	if _, err := d.database.Collection(col).InsertMany(d.context, docs); err != nil {
		Logger.Error(err)
	}
}

func (d *database) UploadFile(bucket BucketName, filename string, id primitive.ObjectID, file *os.File) {
	var b *gridfs.Bucket
	if bucket == Keylog {
		b = d.bucketKeylog
	} else {
		b = d.bucketPcap
	}

	err := b.UploadFromStreamWithID(id, filename, file)
	if err != nil {
		Logger.Error(err)
	}
}

func (d *database) ReportExists(identifier string) bool {
	r := d.collections.containers.FindOne(d.context, bson.D{{"Identifier", identifier}})
	if r.Err() == mongo.ErrNoDocuments {
		return false
	} else if r.Err() != nil {
		Logger.Error(r.Err())
		return false
	}

	return true
}

