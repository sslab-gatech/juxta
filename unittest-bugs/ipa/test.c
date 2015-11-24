// Testing interprocedual analysis.
extern int foo(int);

int main(int argc, char **argv) 
{
  int res = foo(argc);
  if (res > 0)
    return 0;
  return 1;
}
