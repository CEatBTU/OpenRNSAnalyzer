#include <stdio.h>

int main() {
  int a, b, c;
  scanf("%d", &a);
  scanf("%d", &b);
  scanf("%d", &c);
  c = (a + b) ^ c;
  printf("%d\n", c);
  scanf("%d", &a);
  scanf("%d", &b);
  scanf("%d", &c);
  c = a + (b ^ c);
  printf("%d\n", c);
  return 0;
}
