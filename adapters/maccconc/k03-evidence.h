/* SPDX-License-Identifier: Apache-2.0
 * Project K03 evidence adapter. Uses the pinned MAccConc iterators/control API.
 * Include after runner-common.h and prep_di_for_aba_test().
 */
#include <filesystem>
#include <fstream>
#include <string>
#include <sys/stat.h>

namespace k03 {
namespace fs = std::filesystem;
using Stack = std::vector<kcov_di_stack_elem>;
static fs::path run_directory;
static std::string stdout_path, stderr_path;

static FILE *new_file(const fs::path &path) {
  FILE *file = fopen(path.c_str(), "wx");
  if (!file) err(1, "create %s", path.c_str());
  return file;
}
static void close_file(FILE *file) {
  if (ferror(file) || fclose(file)) err(1, "write evidence");
}
static void new_directory(const fs::path &path) {
  if (!fs::create_directory(path)) errx(1, "output directory already exists: %s", path.c_str());
  if (chmod(path.c_str(), 0700)) err(1, "chmod output directory");
}
static void stack_json(FILE *file, const Stack &stack) {
  fputc('[', file);
  for (size_t i=0; i<stack.size(); ++i) {
    if (i) fputc(',', file);
    fprintf(file, "{\"ip\":\"0x%016llx\",\"parent_idx\":%llu}",
            (unsigned long long)stack[i].ip, (unsigned long long)stack[i].parent_idx);
  }
  fputc(']', file);
}
static bool same_stack(const Stack &a, const Stack &b) {
  if (a.size()!=b.size()) return false;
  for (size_t i=0; i<a.size(); ++i)
    if (a[i].ip!=b[i].ip || a[i].parent_idx!=b[i].parent_idx) return false;
  return true;
}
static void save_plan(const fs::path &path, const Stack &stack) {
  FILE *file=new_file(path);
  fprintf(file, "MACCCONC_K03_PLAN_V1\nspin_limit %lu\nrole A\ncount %zu\n", SPIN_LIMIT, stack.size());
  for (const auto &element:stack)
    fprintf(file, "%016llx %llu\n", (unsigned long long)element.ip,
            (unsigned long long)element.parent_idx);
  close_file(file);
}
static Stack load_plan(const fs::path &path) {
  std::ifstream file(path);
  std::string magic,key,role,extra;
  unsigned long spin=0;
  size_t count=0;
  if (!(file>>magic) || magic!="MACCCONC_K03_PLAN_V1" ||
      !(file>>key>>spin) || key!="spin_limit" || spin==0 || spin>1000000000UL ||
      !(file>>key>>role) || key!="role" || role!="A" ||
      !(file>>key>>count) || key!="count" || count<2 || count>32)
    errx(1, "invalid K03 plan header");
  Stack stack;
  for (size_t i=0; i<count; ++i) {
    unsigned long long ip=0,index=0;
    if (!(file>>std::hex>>ip>>std::dec>>index) || ip<0xffffffff80000000ULL)
      errx(1, "invalid K03 stack element");
    stack.push_back({.ip=ip,.parent_idx=index});
  }
  if (file>>extra) errx(1, "unexpected trailing K03 plan data");
  if (!file.eof()) errx(1, "cannot read K03 plan");
  SPIN_LIMIT=spin;
  return stack;
}
static void prepare_output(const fs::path &path, const Stack *stack) {
  new_directory(path);
  run_directory=path;
  if (stack) save_plan(path/"plan.txt",*stack);
  stdout_path=(path/"testcase.stdout.txt").string();
  stderr_path=(path/"testcase.stderr.txt").string();
  k03_child_stdout_path=stdout_path.c_str();
  k03_child_stderr_path=stderr_path.c_str();
}
static bool valid_words(const KcovTrace &trace) {
  for (size_t offset=0; offset<trace.data.size();) {
    auto type=trace.data[offset]&KCOV_RECORDFLAG_TYPEMASK;
    size_t length=0;
    switch(type) {
      case KCOV_RECORDFLAG_TYPE_ENTRY:length=2;break;
      case KCOV_RECORDFLAG_TYPE_MEMORY:length=5;break;
      case KCOV_RECORDFLAG_TYPE_NORMAL:case KCOV_RECORDFLAG_TYPE_EXIT:
      case KCOV_RECORDFLAG_TYPE_EESUM:case KCOV_RECORDFLAG_TYPE_WAIT:
      case KCOV_RECORDFLAG_TYPE_WAKE:length=1;break;
      default:return false;
    }
    if (length>trace.data.size()-offset) return false;
    offset+=length;
  }
  return true;
}
struct TraceStats {
  size_t events=0,memories=0,waits=0,wakes=0,wait1=0,wake0=0,timeouts=0;
  size_t target_matches=0,adjacent_target_hits=0;
};
static TraceStats export_events(size_t thread, KcovTrace &trace, const Stack *target) {
  TraceStats stats;
  FILE *file=new_file(run_directory/(thread==0?"A.events.jsonl":"B.events.jsonl"));
  unsigned long previous=~0UL,before_previous=~0UL;
  unsigned int previous_bit=~0U,before_previous_bit=~0U;
  bool previous_timeout=false;
  for (KcovTraceIterWithStack it(thread,&trace);!it.at_end();it.advance()) {
    unsigned long type=it.record_type();
    fprintf(file,"{\"thread\":\"%c\",\"word_index\":%lu,\"record_type\":\"0x%016lx\"",
            thread==0?'A':'B',it.get_index(),type);
    unsigned int bit=~0U;
    bool timeout=false;
    if (type==KCOV_RECORDFLAG_TYPE_MEMORY) {
      auto *m=it.mar();
      Stack stack=it.get_di_stack();
      fprintf(file,",\"kind\":\"MEMORY\",\"ip\":\"0x%016lx\",\"address\":\"0x%016llx\","
                   "\"size\":%u,\"flags\":%u,\"value\":\"0x%016llx\",\"timestamp\":\"0x%016llx\",\"stack\":",
              it.ip_address(),(unsigned long long)m->data_address,m->size,m->flags,
              (unsigned long long)m->value,(unsigned long long)m->time);
      stack_json(file,stack);
      ++stats.memories;
      if (target && same_stack(stack,*target)) {
        ++stats.target_matches;
        if (before_previous==KCOV_RECORDFLAG_TYPE_WAKE && before_previous_bit==0 &&
            previous==KCOV_RECORDFLAG_TYPE_WAIT && previous_bit==1 && !previous_timeout)
          ++stats.adjacent_target_hits;
      }
    } else if(type==KCOV_RECORDFLAG_TYPE_WAIT || type==KCOV_RECORDFLAG_TYPE_WAKE) {
      bit=it.wakewait_bit_idx();
      timeout=type==KCOV_RECORDFLAG_TYPE_WAIT && it.wait_timed_out();
      fprintf(file,",\"kind\":\"%s\",\"flagidx\":%u,\"timed_out\":%s",
              type==KCOV_RECORDFLAG_TYPE_WAIT?"WAIT":"WAKE",bit,timeout?"true":"false");
      if(type==KCOV_RECORDFLAG_TYPE_WAIT) { ++stats.waits; if(bit==1) ++stats.wait1; }
      else { ++stats.wakes; if(bit==0) ++stats.wake0; }
      if(timeout) ++stats.timeouts;
    } else if(type==KCOV_RECORDFLAG_TYPE_ENTRY) {
      fprintf(file,",\"kind\":\"ENTRY\",\"ip\":\"0x%016lx\",\"caller_ip\":\"0x%016lx\"",
              it.ip_address(),it.caller_ip());
    } else if(type==KCOV_RECORDFLAG_TYPE_EESUM) {
      fprintf(file,",\"kind\":\"EESUM\",\"delta\":%d,\"minimum_delta\":%d",it.eesum_delta(),it.eesum_mindelta());
    } else {
      fprintf(file,",\"kind\":\"%s\",\"ip\":\"0x%016lx\"",
              type==KCOV_RECORDFLAG_TYPE_EXIT?"EXIT":"NORMAL",it.ip_address());
    }
    fprintf(file,"}\n");
    ++stats.events;
    before_previous=previous; before_previous_bit=previous_bit;
    previous=type; previous_bit=bit; previous_timeout=timeout;
  }
  close_file(file);
  return stats;
}
static void stats_json(FILE *file,const TraceStats &s) {
  fprintf(file,"{\"events\":%zu,\"memory_records\":%zu,\"waits\":%zu,\"wakes\":%zu,"
               "\"wait1\":%zu,\"wake0\":%zu,\"timeouts\":%zu,\"target_matches\":%zu,\"adjacent_target_hits\":%zu}",
          s.events,s.memories,s.waits,s.wakes,s.wait1,s.wake0,s.timeouts,s.target_matches,s.adjacent_target_hits);
}
static bool save_run(bool sequential,const Stack *target,bool loaded_from_file) {
  KcovTrace traces[2]={KcovTrace(0),KcovTrace(1)};
  bool overflow=false,well_formed=true;
  for(size_t t=0;t<2;++t) {
    unsigned long count=kcov_insts[t].cover_n;
    if(count>=COVER_SIZE-6) overflow=true;
    unsigned long bounded=std::min(count,(unsigned long)COVER_SIZE-1);
    FILE *raw=new_file(run_directory/(t==0?"A.words":"B.words"));
    for(unsigned long i=1;i<=bounded;++i) fprintf(raw,"%016lx\n",kcov_insts[t].cover[i]);
    close_file(raw);
    traces[t].data.assign(kcov_insts[t].cover+1,kcov_insts[t].cover+1+bounded);
    well_formed=well_formed && valid_words(traces[t]);
  }
  bool child_ok=k03_control->waitpid_result>0 && WIFEXITED(k03_control->child_status) &&
                WEXITSTATUS(k03_control->child_status)==0;
  bool finished=child_ok && k03_control->a_done && k03_control->b_done &&
                k03_control->reset_called && k03_control->reset_rc==0;
  FILE *partial=new_file(run_directory/"run.partial.json");
  fprintf(partial,"{\"child_status\":%d,\"child_ok\":%s,\"overflow\":%s,\"raw_words_well_formed\":%s}\n",
          k03_control->child_status,child_ok?"true":"false",overflow?"true":"false",well_formed?"true":"false");
  close_file(partial);
  TraceStats a,b;
  if(well_formed && !overflow) {
    a=export_events(0,traces[0],target);
    b=export_events(1,traces[1],nullptr);
  }
  bool transport=finished && k03_control->gate_called && k03_control->gate_rc==0 &&
                 k03_control->b_wake_called && k03_control->b_wake_rc==0;
  bool control_valid=transport && well_formed && !overflow && a.memories && b.memories;
  if(sequential) control_valid=control_valid && k03_control->a_wake_called && k03_control->a_wake_rc==0 && a.waits==0;
  else control_valid=control_valid && a.waits==1 && a.wait1==1 && a.timeouts==0 &&
                     a.wakes==1 && a.wake0==1 && a.target_matches==1 && a.adjacent_target_hits==1;
  FILE *file=new_file(run_directory/"run.json");
  fprintf(file,"{\"schema_version\":1,\"roles\":{\"A\":\"test_thread1\",\"B\":\"test_thread2\"},"
               "\"sequential_A_B\":%s,\"plan_loaded_from_file\":%s,\"spin_limit\":%lu,"
               "\"child_status\":%d,\"child_ok\":%s,\"a_done\":%s,\"b_done\":%s,"
               "\"gate0\":{\"called\":%s,\"rc\":%d,\"errno\":%d},"
               "\"b_completed_wake1\":{\"called\":%s,\"rc\":%d,\"errno\":%d},"
               "\"a_completed_wake0\":{\"called\":%s,\"rc\":%d,\"errno\":%d},"
               "\"reset\":{\"called\":%s,\"rc\":%d,\"errno\":%d},"
               "\"buffer_words\":%u,\"A_words\":%lu,\"B_words\":%lu,"
               "\"overflow\":%s,\"raw_words_well_formed\":%s,\"control_valid\":%s,"
               "\"safe_to_continue\":%s,\"A\":",
          sequential?"true":"false",loaded_from_file?"true":"false",SPIN_LIMIT,
          k03_control->child_status,child_ok?"true":"false",k03_control->a_done?"true":"false",k03_control->b_done?"true":"false",
          k03_control->gate_called?"true":"false",k03_control->gate_rc,k03_control->gate_errno,
          k03_control->b_wake_called?"true":"false",k03_control->b_wake_rc,k03_control->b_wake_errno,
          k03_control->a_wake_called?"true":"false",k03_control->a_wake_rc,k03_control->a_wake_errno,
          k03_control->reset_called?"true":"false",k03_control->reset_rc,k03_control->reset_errno,
          COVER_SIZE,kcov_insts[0].cover_n,kcov_insts[1].cover_n,
          overflow?"true":"false",well_formed?"true":"false",control_valid?"true":"false",finished?"true":"false");
  stats_json(file,a); fprintf(file,",\"B\":"); stats_json(file,b); fprintf(file,"}\n"); close_file(file);
  if(!finished || overflow || !well_formed) errx(1,"K03 incomplete execution or invalid trace; evidence retained");
  return control_valid;
}
} // namespace k03
