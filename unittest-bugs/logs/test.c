int foo(int x) 
{
	x = x + 1;
	if (x > 2)
		x++;
	else {
		x += 2;
		x *= 2;
	}
	return x;
}

int main(int argc, char *argv[])
{
	return foo(argc);
}
