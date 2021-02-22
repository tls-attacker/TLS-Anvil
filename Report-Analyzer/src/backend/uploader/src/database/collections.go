package database

import "go.mongodb.org/mongo-driver/mongo"

type collections struct {
	containers *mongo.Collection
	results *mongo.Collection
	states *mongo.Collection
}

func newCollections(database *mongo.Database) *collections {
	collections := new(collections)
	collections.containers = database.Collection("testcontainers")
	collections.results = database.Collection("testresults")
	collections.states = database.Collection("testresultstates")
	return collections
}