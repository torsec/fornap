package reference_handler

import (
	"context"
	"ima_verifier"
	"log"

	"github.com/veraison/corim/comid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

func InsertReference(imasCollection *mongo.Collection, ctx context.Context, referenceValue ima_verifier.RefID) {
	_, err := imasCollection.InsertOne(ctx, referenceValue)
	if err != nil {
		log.Fatal("Error inserting record:", err)
	}
	log.Println("Inserted object with the following whitelistID:", referenceValue.Id)
}

func ReadReference(imasCollection *mongo.Collection, ctx context.Context, id string) ima_verifier.RefID {
	var imaR ima_verifier.RefID
	if err := imasCollection.FindOne(ctx, bson.M{"id": id}).Decode(&imaR); err != nil {
		log.Fatal(err)
		return ima_verifier.RefID{Id: "", References: comid.ReferenceValue{}}
	}
	return imaR
}

func UpdateReference(imasCollection *mongo.Collection, ctx context.Context, mongoId string, id string, ima comid.ReferenceValue) {
	mongoID, err := primitive.ObjectIDFromHex(mongoId)

	if err != nil {
		log.Fatal(err)
	}

	result, err := imasCollection.UpdateOne(
		ctx,
		bson.M{"_id": mongoID},
		bson.D{
			{Key: "$set", Value: ima_verifier.RefID{Id: id, References: ima}}},
	)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Updated %v Document(s)!\n", result.ModifiedCount)
}

func DeleteReference(imasCollection *mongo.Collection, ctx context.Context, id string) {
	resultDeletion, err := imasCollection.DeleteOne(ctx, bson.M{"id": id})

	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Removed %v document(s)\n", resultDeletion.DeletedCount)
}
