package main

/*
	build steps:
	1. download clamav source code http://www.clamav.net/
	2. build && install
		./configure --prefix=/opt/crossbuild/x86_64 --enable-static
		make && sudo make install
	3. go get -d github.com/mirtchovski/clamav
	4. build lib
		CGO_CFLAGS=-I/opt/crossbuild/x86_64/include CGO_LDFLAGS=-L/opt/crossbuild/x86_64/lib64 go install github.com/mirtchovski/clamav
	5. build this
*/
import (
	"context"
	"os"
	"path/filepath"

	"github.com/Sirupsen/logrus"
	"github.com/mirtchovski/clamav"
)

type ClamAVResult ClamLiteResult

// Workers receive file names on 'in', scan them, and output the results on 'out'

type clamavCb interface {
	preScanCb(fd int, ftype string, context interface{})
	postScanCb(fd int, result clamav.ErrorCode, virname string, context interface{})
	hashCb(fd int, size uint64, md5 []byte, virname string, context interface{})
}

type ClamAV struct {
	debug  bool
	engine *clamav.Engine
}

func (c *ClamAV) preCacheCb(fd int, ftype string, context interface{}) clamav.ErrorCode {
	if c.debug {
		logrus.Debugf("pre cache callback for %s: fd=%d ftype=%s", context, fd, ftype)
	}

	return clamav.Clean
}

func (c *ClamAV) preScanCb(fd int, ftype string, context interface{}) clamav.ErrorCode {
	if c.debug {
		logrus.Debugf("pre scan callback for %s: fd=%d ftype=%s", context, fd, ftype)
	}

	return clamav.Clean
}

func (c *ClamAV) postScanCb(fd int, result clamav.ErrorCode, virname string, context interface{}) clamav.ErrorCode {
	if c.debug {
		logrus.Debugf("post scan callback for %s: fd=%d result=%s virus=%s", context, fd, clamav.StrError(result), virname)
	}

	return clamav.Clean
}

func (c *ClamAV) hashCb(fd int, size uint64, md5 []byte, virname string, context interface{}) {
	if c.debug {
		logrus.Debugf("hash callback for %s: fd=%d size=%d md5=%s virus=%s", context, fd, size, md5, virname)
	}

	return
}

func NewClamAV(dbDir string, debug bool) (*ClamAV, error) {
	var clam ClamAV
	if dbDir == "" {
		dbDir = clamav.DBDir()
	}

	clamav.Init(clamav.InitDefault)
	engine := clamav.New()
	sigs, err := engine.Load(dbDir, clamav.DbStdopt)
	if err != nil {
		//		log.Fatalf("can not initialize ClamAV engine: %v", err)
		return nil, err
	}
	if debug {
		logrus.Debugf("loaded %d signatures", sigs)
	}

	engine.SetPreCacheCallback(clam.preCacheCb)
	engine.SetPreScanCallback(clam.preScanCb)
	engine.SetPostScanCallback(clam.postScanCb)
	engine.SetHashCallback(clam.hashCb)

	engine.Compile()
	clam.engine = engine

	return &clam, nil
}

func (c *ClamAV) ScanMem(mem []byte) (string, error) {
	fmap := clamav.OpenMemory(mem)
	defer clamav.CloseMemory(fmap)
	engine := c.engine

	virus, _, err := engine.ScanMapCb(fmap, clamav.ScanStdopt|clamav.ScanAllmatches, "eicar memorytest")
	if virus != "" {
		return virus, nil
	} else if err != nil {
		logrus.Error("[security:ClamavScanFile] error ", err)
	}
	return "", err
}

func (c *ClamAV) ScanFile(filename string) (string, error) {
	engine := c.engine
	virus, _, err := engine.ScanFileCb(filename, clamav.ScanStdopt|clamav.ScanAllmatches, filename)
	if virus != "" {
		return virus, nil
	} else if err != nil {
		logrus.Error("[security:ClamavScanFile] error ", err)
	}
	return "", err
}

func (c *ClamAV) ScanDir(dir string, ctx context.Context) <-chan *ClamAVResult {
	resultCh := make(chan *ClamAVResult, 256)
	go func(ctx context.Context, dir string, outChn chan<- *ClamAVResult) {
		filepath.Walk(dir,
			func(filename string, fi os.FileInfo, err error) error { //遍历目录
				if err != nil { //忽略错误
					return nil
				}
				if ctx.Err() != nil {
					logrus.Warn("[security:ClamavScanDir] cancel error ", ctx.Err())
					return ctx.Err()
				}

				if fi.Mode().IsRegular() {
					r, err := c.ScanFile(filename)
					logrus.Println(filename, " ", r, " ", err)
					if err == nil && r != "" {
						outChn <- &ClamAVResult{
							FilePath: filename,
							Result:   r,
						}
					}
				}
				return nil
			})
		close(outChn)
	}(ctx, dir, resultCh)
	return resultCh
}
