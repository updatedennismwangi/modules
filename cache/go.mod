module github.com/updatedennismwangi/cache

go 1.19

require (
	github.com/updatedennismwangi/redis v1.0.0
	github.com/updatedennismwangi/postgres v1.0.0
)

replace (
	github.com/updatedennismwangi/redis => ../redis
	github.com/updatedennismwangi/postgres => ../postgres
)