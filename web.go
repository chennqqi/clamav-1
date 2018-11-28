package main

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	utime "github.com/chennqqi/goutils/time"

	"github.com/chennqqi/goutils/persistlist"
	"github.com/gin-gonic/gin"
	"github.com/malice-plugins/go-plugin-utils/utils"
)

type Web struct {
	fileto utime.Duration
	zipto  utime.Duration

	callback string
	to       utime.Duration

	tmpDir   string
	indexDir string

	scanQuit chan struct{}
	server   *http.Server
	cancel   context.CancelFunc
	list     persistlist.PersistList

	clav *ClamAV
}

type Job struct {
	Cb   string         `json:"cb"`
	Dir  string         `json:"dir"`
	Name string         `json:"name"`
	Tid  string         `json:"tid"`
	To   utime.Duration `json:"to"`
}

func NewWeb(dataDir, indexDir string) (*Web, error) {
	var web Web

	list, err := persistlist.NewNodbList(indexDir, PERSIST_LISTKEY_NAME)
	if err != nil {
		return nil, err
	}

	err = os.MkdirAll(dataDir, 0755)
	if !os.IsExist(err) && err != nil {
		fmt.Printf("mkdir tmp dir error: \n", err)
		return nil, err
	}

	web.tmpDir = dataDir
	web.list = list
	return &web, nil
}

func (s *Web) Shutdown(ctx context.Context) error {
	err := s.server.Shutdown(ctx)
	s.cancel()
	<-s.scanQuit
	return err
}

func (s *Web) scanRoute(ctx context.Context) {
	ticker := time.NewTicker(time.Second / 2)
	defer ticker.Stop()
	list := s.list

__FOR_LOOP:
	for {
		select {
		case <-ticker.C:
			for {
				var j Job
				err := list.Pop(&j)
				if err == persistlist.ErrNil {
					break
				}
				if err != nil {
					fmt.Println("[scanRoute] POP ERROR:", err)
					continue
				}
				r, _ := s.scanDir(tmpDir, to)
				r1 := strings.Replace(r, f.Name(), upf.Filename, -1)
				s.doCallback(j.Cb, r1)
				os.RemoveAll(j.Dir)
			}
		case <-ctx.Done():
			break __FOR_LOOP
		}
	}
	close(s.scanQuit)
}

func (s *Web) version(c *gin.Context) {
	txt, _ := ioutil.ReadFile("/malware/VERSION")
	c.Data(200, "", txt)
}

func (s *Web) scanFile(c *gin.Context) {
	var err error
	to := s.fileto
	timeout, ok := c.GetQuery("timeout")
	if ok {
		tto, err = time.ParseDuration(timeout)
		if err == nil {
			to = utime.Duration(s.fileto)
		}
	}

	upf, err := c.FormFile("filename")
	if err != nil {
		c.JSON(400,
			CR{
				Message: fmt.Sprintf("get form err: %s", err.Error()),
				Status:  1,
			})
		return
	}
	src, err := upf.Open()
	if err != nil {
		c.JSON(400,
			CR{
				Message: fmt.Sprintf("open form err: %s", err.Error()),
				Status:  1,
			})
		return
	}
	defer src.Close()
	tmpDir, err := ioutil.TempDir(s.tmpDir, "file")
	if err != nil {
		c.JSON(500,
			CR{
				Message: fmt.Sprintf("net tmp direrr: %s", err.Error()),
				Status:  1,
			})
		return
	}
	f, err := ioutil.TempFile(tmpDir, "scan_")
	if err != nil {
		c.JSON(400,
			CR{
				Message: fmt.Sprintf("create temp file err: %s", err.Error()),
				Status:  1,
			})
		return
	}
	io.Copy(f, src)
	f.Close()

	cb, exist := c.GetQuery("callback")
	if exist {
		list := s.list
		var j Job
		j.Cb = cb
		j.Dir = tmpDir
		j.Name = upf.Filename
		j.Tid = 0
		j.To = to
		pending, err := list.Push(&j)
		if err != nil {
			c.JSON(400,
				CR{
					Message: fmt.Sprintf("add to task list err: %s", err.Error()),
					Status:  1,
				})
			return
		} else {
			c.JSON(200,
				CR{
					Message: fmt.Sprintf("pending: %d", pending),
					Status:  0,
				})
			return
		}
	} else {
		defer os.Remove(tmpDir)
		defer os.Remove(f.Name())

		r, _ := s.scanDir(tmpDir, to)
		c.Header("Content-type", "application/json")
		r1 := strings.Replace(r, f.Name(), upf.Filename, -1)
		s.doCallback(c, r1)
		c.String(200, r1)
	}
}

func (s *Web) flush(c *gin.Context) {
	list := s.list
	var count int
	var ret struct {
		CR
		Count int `json:"count"`
	}

	for {
		var task Job
		err := list.Pop(&task)
		if err == persistlist.ErrNil {
			break
		} else if err != nil {
			ret.Message = err.Error()
			ret.Status = 1
			ret.Count = count
			c.JSON(500, &ret)
		}
		os.RemoveAll(task.Dir)
		count++
	}
	ret.Message = "OK"
	ret.Status = 0
	ret.Count = count
	c.JSON(200, &ret)
}

func Unzip(src, dest string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer func() {
		if err := r.Close(); err != nil {
			panic(err)
		}
	}()

	os.MkdirAll(dest, 0755)

	// Closure to address file descriptors issue with all the deferred .Close() methods
	extractAndWriteFile := func(f *zip.File) error {
		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer func() {
			if err := rc.Close(); err != nil {
				panic(err)
			}
		}()

		path := filepath.Join(dest, f.Name)

		if f.FileInfo().IsDir() {
			os.MkdirAll(path, f.Mode())
		} else {
			os.MkdirAll(filepath.Dir(path), f.Mode())
			f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
			if err != nil {
				return err
			}
			defer func() {
				if err := f.Close(); err != nil {
					panic(err)
				}
			}()

			_, err = io.Copy(f, rc)
			if err != nil {
				return err
			}
		}
		return nil
	}

	for _, f := range r.File {
		err := extractAndWriteFile(f)
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *Web) Run(port int) {
	scanctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	s.scanQuit = make(chan struct{})
	go s.scanRoute(scanctx)

	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()
	r.POST("/zip", s.scanZip)
	r.POST("/file", s.scanFile)
	r.GET("/queued", s.queued)
	r.POST("/flush", s.flush)
	r.GET("/version", s.scanFile)

	httpServer := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: r,
	}
	s.server = httpServer
	return httpServer.ListenAndServe()
}

func (s *Web) scanZip(c *gin.Context) {
	var err error
	upf, err := c.FormFile("zipname")
	if err != nil {
		c.String(http.StatusBadRequest, fmt.Sprintf("get form err: %s", err.Error()))
		return
	}
	to := s.zipto
	timeout, ok := c.GetQuery("timeout")
	if ok {
		to, err = time.ParseDuration(timeout)
		if err != nil {
			to = s.zipto
		}
	}

	src, err := upf.Open()
	if err != nil {
		c.String(http.StatusBadRequest, fmt.Sprintf("get form err: %s", err.Error()))
		return
	}
	defer src.Close()
	f, err := ioutil.TempFile(s.tmpDir, "zip_")
	if err != nil {
		c.String(http.StatusBadRequest, fmt.Sprintf("new tmp file err: %s", err.Error()))
		return
	}
	defer os.Remove(f.Name())
	io.Copy(f, src)
	f.Close()

	tmpDir, err := ioutil.TempDir(s.tmpDir, "scan_")
	if err != nil {
		c.String(http.StatusInternalServerError,
			fmt.Sprintf("save zip file err: %s", err.Error()))
		return
	}
	defer os.Remove(tmpDir)

	if err = utils.Unzip(f.Name(), tmpDir); err != nil {
		c.String(http.StatusInternalServerError,
			fmt.Sprintf("unzip zip file err: %s", err.Error()))
		return
	}
	defer os.RemoveAll(tmpDir)

	//TODO:
	r, _ := s.scanDir(tmpDir, to)
	c.Header("Content-type", "application/json")
	r1 := strings.Replace(r, tmpDir, "", -1)
	s.doCallback(c, r1)
	c.String(200, r1)
}

func (s *Web) doCallback(cb string, r string) {
	go func(r, cb string) {
		body := strings.NewReader(r)
		resp, err := http.Post(cb, "application/json", body)
		if err != nil {
			fmt.Printf("do callback(%v) error: %v\n", cb, err)
			return
		}
		io.Copy(ioutil.Discard, resp.Body)
		resp.Body.Close()
	}(r, callback)
}

func (s *Web) doCallback(c *gin.Context, r string) {
	callback := c.Query("callback")
	if callback == "" {
		callback = s.callback
	}
	if callback != "" {
		go func(r string) {
			body := strings.NewReader(r)
			http.Post(callback, "application/json", body)
		}(r)
	}
}

func (s *Web) scanDir(dir string, to time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.TODO(), to)
	defer cancel()
	clav := s.clav
	outChan := clav.ScanDir(dir, ctx)
	var results []*ClamAVResult
	for {
		r, ok := <-outChan
		if !ok {
			break
		}
		results = append(results, r)
	}
	txt, err := json.Marshal(results)
	return string(txt), err
}
