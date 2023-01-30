module github.com/updatedennismwangi/app

go 1.19

replace github.com/updatedennismwangi/runtime => ../runtime

replace github.com/updatedennismwangi/log => ../log

replace github.com/updatedennismwangi/utils => ../utils

require github.com/updatedennismwangi/runtime v1.0.0

require github.com/updatedennismwangi/log v1.0.0

require (
	github.com/joho/godotenv v1.4.0
	github.com/updatedennismwangi/utils v1.0.0
)
