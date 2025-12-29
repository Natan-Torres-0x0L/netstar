#ifndef _NETSTAR_THREADS_H
#define _NETSTAR_THREADS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <netstar-time.h>

#include <pthread.h>

#include <stdbool.h>


#define NETSTAR_THREAD_MUTEX_INITIALIZER PTHREAD_MUTEX_INITIALIZER

typedef pthread_mutex_t netstar_thread_mutex_t;


extern void netstar_thread_mutex_lock(netstar_thread_mutex_t *);
extern void netstar_thread_mutex_unlock(netstar_thread_mutex_t *);


#define NETSTAR_THREAD_COND_INITIALIZER PTHREAD_COND_INITIALIZER

typedef pthread_cond_t netstar_thread_cond_t;

struct netstar_thread_cond_timeout {
  long sec, usec;
};


extern void netstar_thread_cond_timedwait(netstar_thread_cond_t *, netstar_thread_mutex_t *, struct netstar_thread_cond_timeout *);
extern void netstar_thread_cond_wait(netstar_thread_cond_t *, netstar_thread_mutex_t *);

extern void netstar_thread_cond_sendall(netstar_thread_cond_t *);
extern void netstar_thread_cond_send(netstar_thread_cond_t *);

extern void netstar_thread_cond_destroy(netstar_thread_cond_t *);


typedef struct netstar_thread {
  netstar_thread_mutex_t mutex;

// netstar_thread_attr_t attributes;
  pthread_t self;

  bool status, killed;

  void *args;
} netstar_thread_t;

typedef void *(*netstar_thread_routine_t)(void *);


extern netstar_thread_t *netstar_thread_spawn(netstar_thread_routine_t, void *);
extern void netstar_thread_routine(netstar_thread_routine_t, void *);

extern netstar_thread_t *netstar_thread_self(void);

extern void netstar_thread_join(netstar_thread_t *, void **);

extern void netstar_thread_exit(netstar_thread_t *, void *);
extern void netstar_thread_kill(netstar_thread_t *);

extern void netstar_threads_initialize(void);
extern void netstar_threads_deinitialize(void);

#ifdef __cplusplus
}
#endif

#endif
