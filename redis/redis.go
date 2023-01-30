package redis

import (
	"context"
	"fmt"
	rd "github.com/go-redis/redis/v8"
)

// RdClient is the default redis connection object.
var RdClient *rd.Client

var RdContext = context.Background()

// RdOpen establishes a connection to the redis vbet.
func RdOpen(network string, host string, port int, password string, maxPool int) (*rd.Client, error) {
	var client *rd.Client
	if network != "unix" {
		client = rd.NewClient(&rd.Options{
			Network:  network,
			Addr:     fmt.Sprintf("%s:%d", host, port),
			Password: password,
			DB:       0,
			PoolSize: maxPool,
		})
	} else {
		client = rd.NewClient(&rd.Options{
			Network:  network,
			Addr:     host,
			Password: password,
			DB:       0,
			PoolSize: maxPool,
		})
	}
	_, err := client.Ping(RdContext).Result()
	return client, err
}

// RdClose disconnects and closes the redis connection.
func RdClose(client *rd.Client) {
	if client != nil {
		_ = client.Close()
	}
}

// RdClean find and clean any live redis key.
func RdClean(searchPattern string) {
	var foundedRecordCount = 0
	iter := RdClient.Scan(RdContext, 0, searchPattern, 0).Iterator()
	for iter.Next(RdContext) {
		fmt.Printf("Deleted= %s\n", iter.Val())
		RdClient.Del(RdContext, iter.Val())
		foundedRecordCount++
	}
	if err := iter.Err(); err != nil {
		panic(err)
	}
}
