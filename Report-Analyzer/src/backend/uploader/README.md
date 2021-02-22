## Build
```
docker build -t uploader .
```

## Run
* The program searches for `testresults.json` files recursively in `/path/to/folder` and uploads the reports
* A mongoDB instance must be reachable at `localhost:27017`
    * The url of the DB can be changed with `-db`
* Use `-h` to see all available options of the uploader 

```
docker run --rm -it --network host -v /path/to/folder:/upload uploader
```

