// Package ctl은 같은 서버의 root가 실행한 `douve-agent expose` 같은 명령을 Agent 데몬에 전달하는
// 유닉스 소켓이다 (상태 디렉터리, 권한 600 — root만).
//
//	CLI ──(JSON 한 줄)──▶ 데몬 ──WebSocket──▶ Hub ──▶ 응답
package ctl

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"github.com/5sick/douve/agent/internal/i18n"
	"net"
	"os"
	"path/filepath"
	"time"
)

// Request는 CLI가 보내는 요청이다.
type Request struct {
	Op   string `json:"op"` // expose | unexpose | list
	Port int    `json:"port,omitempty"`
	Name string `json:"name,omitempty"`
	Host string `json:"host,omitempty"`
	Path string `json:"path,omitempty"`
	Auth string `json:"auth,omitempty"` // douve | public
	Lang string `json:"lang,omitempty"` // CLI 언어 (Hub가 오류 문구를 이 언어로)
}

// Response는 데몬의 답이다.
type Response struct {
	OK       bool              `json:"ok"`
	Error    string            `json:"error,omitempty"`
	URL      string            `json:"url,omitempty"`
	Warning  string            `json:"warning,omitempty"`
	Services []json.RawMessage `json:"services,omitempty"`
}

func SocketPath(stateDir string) string { return filepath.Join(stateDir, "ctl.sock") }

// Handler는 요청을 처리한다 (데몬이 Hub에 물어본다).
type Handler func(ctx context.Context, req Request) Response

// Serve는 소켓을 열고 요청을 받는다. ctx가 끝나면 닫는다.
func Serve(ctx context.Context, stateDir string, h Handler) error {
	path := SocketPath(stateDir)
	_ = os.MkdirAll(stateDir, 0o700)
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return err
	}
	go func() {
		<-ctx.Done()
		ln.Close()
		os.Remove(path)
	}()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(30 * time.Second))
				var req Request
				line, err := bufio.NewReader(c).ReadBytes('\n')
				if err != nil {
					return
				}
				resp := Response{Error: "요청 형식 오류"}
				if json.Unmarshal(line, &req) == nil {
					rctx, cancel := context.WithTimeout(ctx, 20*time.Second)
					resp = h(rctx, req)
					cancel()
				}
				b, _ := json.Marshal(resp)
				_, _ = c.Write(append(b, '\n'))
			}(c)
		}
	}()
	return nil
}

// Call은 CLI 쪽: 데몬에 요청을 보내고 답을 받는다.
func Call(stateDir string, req Request) (Response, error) {
	c, err := net.DialTimeout("unix", SocketPath(stateDir), 3*time.Second)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return Response{}, errors.New(i18n.T("root 권한이 필요합니다 (sudo로 실행하세요)"))
		}
		return Response{}, errors.New(i18n.T("douve-agent 서비스에 연결할 수 없습니다 (systemctl status douve-agent)"))
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	b, _ := json.Marshal(req)
	if _, err := c.Write(append(b, '\n')); err != nil {
		return Response{}, err
	}
	line, err := bufio.NewReader(c).ReadBytes('\n')
	if err != nil {
		return Response{}, err
	}
	var resp Response
	if err := json.Unmarshal(line, &resp); err != nil {
		return Response{}, err
	}
	return resp, nil
}
