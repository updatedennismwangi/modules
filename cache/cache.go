package cache

import (
	"fmt"
	. "github.com/updatedennismwangi/postgres"
	. "github.com/updatedennismwangi/redis"
)

// RedisSettings holds credentials for redis client.
type RedisSettings struct {
	Network  string `json:"network"`
	Host     string `json:"host"`
	Password string `json:"password"`
	MaxPool  int    `json:"max_pool"`
	Port     int    `json:"port"`
}

// DbConfig holds credentials for database(postgresSQL) client.
type DbConfig struct {
	Network  string `json:"network"`
	Host     string `json:"host"`
	Username string `json:"username"`
	Password string `json:"password"`
	Name     string `json:"name"`
	Port     int    `json:"port"`
	MaxPool  int    `json:"max_pool"`
}

// DbSettings holds the master(Write) and slave(Read) database credentials.
type DbSettings struct {
	Master DbConfig `json:"master"`
	Read   DbConfig `json:"read"`
}

// StartCaches establishes redis and database connections as specified with the bool arguments
// for redis and database with true as enabled.
// It also initializes the redis cache object.
func StartCaches(redis *RedisSettings, database *DbSettings) error {
	var rErr, dErr error
	if redis != nil {
		// Setup redis connection and sync online
		RdClient, rErr = RdOpen(redis.Network, redis.Host, redis.Port, redis.Password, redis.MaxPool)
		if rErr != nil {
			return fmt.Errorf("redis connection error %v", rErr)
		}
	}
	if database != nil {
		// Setup Database
		q := fmt.Sprintf("user=%s password=%s host=%s port=%d dbname=%s pool_max_conns=%d",
			database.Master.Username, database.Master.Password, database.Master.Host,
			database.Master.Port, database.Master.Name, database.Master.MaxPool)
		DbCon, dErr = DbOpen(q)
		if dErr != nil {
			return fmt.Errorf("database connection error %v", dErr)
		}
		q = fmt.Sprintf("user=%s password=%s host=%s port=%d dbname=%s pool_max_conns=%d",
			database.Read.Username, database.Read.Password, database.Read.Host, database.Read.Port,
			database.Read.Name, database.Read.MaxPool)
		DbRead, dErr = DbOpen(q)
		if dErr != nil {
			return fmt.Errorf("database read connection error %v", dErr)
		}
	}
	return nil
}

// StopCaches shuts down the redis and database connections in that order if enabled.
func StopCaches() {
	// Close database
	if DbCon != nil {
		DbClose(DbCon)
	}
	// Close read database
	if DbRead != nil {
		DbClose(DbRead)
	}
	// Close redis
	if RdClient != nil {
		RdClose(RdClient)
	}
}
