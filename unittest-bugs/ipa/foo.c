
int foo(int x) 
{
#ifdef __PATCH__
  if (x > 0)
    return 0;
#endif
  return 1;
}


