// Independent native traffic generator. No third-party dependencies.
package main
import("bufio";"encoding/json";"fmt";"io";"net";"os";"strconv";"strings";"sync";"sync/atomic";"time";"sort")
func main(){
 if len(os.Args)<3{panic("benchdriver backend ADDRESS FILE | load ADDRESS CONCURRENCY SECONDS BYTES")}
 if os.Args[1]=="backend"{
  l,e:=net.Listen("tcp",os.Args[2]);if e!=nil{panic(e)}
  fmt.Println("ready")
  for{c,e:=l.Accept();if e!=nil{return};go func(){defer c.Close();c.SetDeadline(time.Now().Add(30*time.Second));r:=bufio.NewReader(c)
   first,e:=r.ReadString('\n');if e!=nil{return};parts:=strings.Fields(first);if len(parts)<2{return};n,_:=strconv.ParseInt(strings.TrimPrefix(parts[1],"/"),10,64);if n<1||n>256<<20{return}
   for size:=len(first);;{line,e:=r.ReadString('\n');size+=len(line);if e!=nil||size>65536{return};if line=="\r\n"{break}}
   f,e:=os.Open(os.Args[3]);if e!=nil{return};defer f.Close();io.CopyN(c,f,n)
  }()}
 }
 concurrency,_:=strconv.Atoi(os.Args[3]);sec,_:=strconv.ParseFloat(os.Args[4],64);want,_:=strconv.ParseInt(os.Args[5],10,64)
 var total,requests,errors atomic.Int64;var wg sync.WaitGroup;var mu sync.Mutex;var samples []int64
 start:=time.Now();end:=start.Add(time.Duration(sec*float64(time.Second)))
 for i:=0;i<concurrency;i++{wg.Add(1);go func(){defer wg.Done();local:=make([]int64,0,4096)
  for time.Now().Before(end){
   tick:=time.Now();c,e:=net.DialTimeout("tcp",os.Args[2],3*time.Second);if e!=nil{errors.Add(1);continue}
   c.SetDeadline(time.Now().Add(15*time.Second));_,e=fmt.Fprintf(c,"GET /%d HTTP/1.1\r\nHost: bench.test\r\nConnection: close\r\n\r\n",want)
   n,err:=io.Copy(io.Discard,c);c.Close();if e!=nil||err!=nil||n!=want{errors.Add(1)}else{total.Add(n);requests.Add(1);if len(local)<100000{local=append(local,time.Since(tick).Microseconds())}}
  };mu.Lock();samples=append(samples,local...);mu.Unlock()
 }()}
 wg.Wait();elapsed:=time.Since(start).Seconds();sort.Slice(samples,func(i,j int)bool{return samples[i]<samples[j]})
 var p50,p95 int64;if len(samples)>0{p50=samples[len(samples)/2];p95=samples[len(samples)*95/100]}
 json.NewEncoder(os.Stdout).Encode(map[string]any{"elapsed_seconds":elapsed,"bytes":total.Load(),"requests":requests.Load(),"errors":errors.Load(),
 "gbps":float64(total.Load())*8/elapsed/1e9,"requests_per_second":float64(requests.Load())/elapsed,"p50_ms":float64(p50)/1000,"p95_ms":float64(p95)/1000})
}
