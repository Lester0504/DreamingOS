# Optional local inference products; the platform/webd itself does not link RKLLM.
# RKLLM_INCLUDE points at Rockchip release-v1.3.1 librkllm_api/include.
CC ?= cc
CXX ?= c++
OUT ?= .
CPPFLAGS += -I$(RKLLM_INCLUDE)
LDLIBS_LOCAL = -ljson-c -lsqlite3 -lcurl -lcrypto -lpthread
all: $(OUT)/dreamingwrt-ai-locald $(OUT)/dreamingwrt-ai-rkllm
$(OUT)/dreamingwrt-ai-locald: locald.c local_ipc.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ locald.c $(LDFLAGS) $(LDLIBS_LOCAL)
$(OUT)/dreamingwrt-ai-rkllm: rkllm_worker.cc local_ipc.h
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -o $@ rkllm_worker.cc $(LDFLAGS) -ljson-c -lpthread -ldl
.PHONY: all
