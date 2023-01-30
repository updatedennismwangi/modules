package postgres

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v4/pgxpool"
)

// DbCon is the default database read/write connection pool.
var DbCon *pgxpool.Pool

// DbRead is the default database read only connection pool.
var DbRead *pgxpool.Pool

// DbOpen establishes a connection pool to the database vbet.
func DbOpen(primaryConn string) (*pgxpool.Pool, error) {
	conn, err := pgxpool.Connect(context.Background(), primaryConn)
	return conn, err
}

// DbClose disconnects and closes the database connection.
func DbClose(dbCon *pgxpool.Pool) {
	defer func(conn *pgxpool.Pool, ctx context.Context) {
		if conn != nil {
			conn.Close()
		}
	}(dbCon, context.Background())
}

// DbStats provides the current database statistics.
// Example : max_conns, total_cons, idle_cons.
func DbStats(dbCon *pgxpool.Pool) string {
	return fmt.Sprintf("Db stats max_cons=%d total_cons=%d idle_cons=%d acquired_conns=%d", dbCon.Stat().MaxConns(), dbCon.Stat().TotalConns(), dbCon.Stat().IdleConns(), dbCon.Stat().AcquiredConns())
}
