// from unit test

typedef struct {
	void	*foo;
} mutex_t;

int mutex_lock(mutex_t *l)    {return 0;};
int mutex_unlock(mutex_t *l)  {return 0;};
int mutex_trylock(mutex_t *l) {return 0;};
int mutex_destroy(mutex_t *l) {return 0;};
int mutex_init(mutex_t  *mutex, void *mutexattr) {return 0;};

mutex_t mtx1, mtx2;
mutex_t *pmtx;

#define NULL 0

void
ok1(void)
{
	mutex_lock(&mtx1); // no-warning
  return;
}

void
ok2(void)
{
	mutex_unlock(&mtx1); // no-warning
  return;
}

void
ok3(void)
{
	mutex_lock(&mtx1);	// no-warning
	mutex_unlock(&mtx1);	// no-warning
	mutex_lock(&mtx1);	// no-warning
	mutex_unlock(&mtx1);	// no-warning
  return;
}

void
ok4(void)
{
	mutex_lock(&mtx1);	// no-warning
	mutex_unlock(&mtx1);	// no-warning
	mutex_lock(&mtx2);	// no-warning
	mutex_unlock(&mtx2);	// no-warning
  return;
}

void
ok5(void)
{
	if (mutex_trylock(&mtx1) == 0)	// no-warning
		mutex_unlock(&mtx1);	// no-warning
  return;
}

void
ok8(void)
{
	mutex_lock(&mtx1);	// no-warning
	mutex_lock(&mtx2);	// no-warning
	mutex_unlock(&mtx2);	// no-warning
	mutex_unlock(&mtx1);	// no-warning
  return;
}

void
ok9(void)
{
	mutex_unlock(&mtx1);		// no-warning
	if (mutex_trylock(&mtx1) == 0)	// no-warning
		mutex_unlock(&mtx1);	// no-warning
  return;
}

void
ok10(void)
{
	if (mutex_trylock(&mtx1) != 0)	// no-warning
		mutex_lock(&mtx1);	// no-warning
	mutex_unlock(&mtx1);		// no-warning
  return;
}

void
ok11(void)
{
	mutex_destroy(&mtx1);	// no-warning
  return;
}

void
ok12(void)
{
	mutex_destroy(&mtx1);	// no-warning
	mutex_destroy(&mtx2);	// no-warning
  return;
}

void
ok13(void)
{
	mutex_unlock(&mtx1);	// no-warning
	mutex_destroy(&mtx1);	// no-warning
  return;
}

void
ok14(void)
{
	mutex_unlock(&mtx1);	// no-warning
	mutex_destroy(&mtx1);	// no-warning
	mutex_unlock(&mtx2);	// no-warning
	mutex_destroy(&mtx2);	// no-warning
  return;
}

void
ok15(void)
{
	mutex_lock(&mtx1);	// no-warning
	mutex_unlock(&mtx1);	// no-warning
	mutex_destroy(&mtx1);	// no-warning
  return;
}

void
ok16(void)
{
	mutex_init(&mtx1, NULL);	// no-warning
  return;
}

void
ok17(void)
{
	mutex_init(&mtx1, NULL);	// no-warning
	mutex_init(&mtx2, NULL);	// no-warning
  return;
}

void
ok18(void)
{
	mutex_destroy(&mtx1);		// no-warning
	mutex_init(&mtx1, NULL);	// no-warning
  return;
}

void
ok19(void)
{
	mutex_destroy(&mtx1);		// no-warning
	mutex_init(&mtx1, NULL);	// no-warning
	mutex_destroy(&mtx2);		// no-warning
	mutex_init(&mtx2, NULL);	// no-warning
  return;
}

void
ok20(void)
{
	mutex_unlock(&mtx1);		// no-warning
	mutex_destroy(&mtx1);		// no-warning
	mutex_init(&mtx1, NULL);	// no-warning
	mutex_destroy(&mtx1);		// no-warning
	mutex_init(&mtx1, NULL);	// no-warning
  return;
}

void
ok21(void) {
  mutex_lock(pmtx);    // no-warning
  mutex_unlock(pmtx);  // no-warning
  return;
}

void
ok22(void) {
  mutex_lock(pmtx);    // no-warning
  mutex_unlock(pmtx);  // no-warning
  mutex_lock(pmtx);    // no-warning
  mutex_unlock(pmtx);  // no-warning
  return;
}


void
bad1(void)
{
	mutex_lock(&mtx1);	// no-warning
	mutex_lock(&mtx1);	// expected-warning{{This lock has already been acquired}}
  return;
}

void
bad2(void)
{
	mutex_lock(&mtx1);	// no-warning
	mutex_unlock(&mtx1);	// no-warning
	mutex_lock(&mtx1);	// no-warning
	mutex_lock(&mtx1);	// expected-warning{{This lock has already been acquired}}
  return;
}

void
bad3(void)
{
	mutex_lock(&mtx1);	// no-warning
	mutex_lock(&mtx2);	// no-warning
	mutex_unlock(&mtx1);	// expected-warning{{This was not the most recently acquired lock}}
	mutex_unlock(&mtx2);
  return;
}

void
bad4(void)
{
	if (mutex_trylock(&mtx1)) // no-warning
		return;
	mutex_lock(&mtx2);	// no-warning
	mutex_unlock(&mtx1);	// expected-warning{{This was not the most recently acquired lock}}
  return;
}

void
bad12(void)
{
	mutex_lock(&mtx1);	// no-warning
	mutex_unlock(&mtx1);	// no-warning
	mutex_lock(&mtx1);	// no-warning
	mutex_unlock(&mtx1);	// no-warning
	mutex_unlock(&mtx1);	// expected-warning{{This lock has already been unlocked}}
  return;
}

void
bad13(void)
{
	mutex_lock(&mtx1);	// no-warning
	mutex_unlock(&mtx1);	// no-warning
	mutex_lock(&mtx2);	// no-warning
	mutex_unlock(&mtx2);	// no-warning
	mutex_unlock(&mtx1);	// expected-warning{{This lock has already been unlocked}}
  return;
}

void
bad14(void)
{
	mutex_lock(&mtx1);	// no-warning
	mutex_lock(&mtx2);	// no-warning
	mutex_unlock(&mtx2);	// no-warning
	mutex_unlock(&mtx1);	// no-warning
	mutex_unlock(&mtx2);	// expected-warning{{This lock has already been unlocked}}
  return;
}

void
bad15(void)
{
	mutex_lock(&mtx1);	// no-warning
	mutex_lock(&mtx2);	// no-warning
	mutex_unlock(&mtx2);	// no-warning
	mutex_unlock(&mtx1);	// no-warning
	mutex_lock(&mtx1);	// no-warning
	mutex_unlock(&mtx2);	// expected-warning{{This lock has already been unlocked}}
  return;
}

int main(int argc, char *argv[]) {}