/* SPDX-License-Identifier: Apache-2.0
 * K03 infrastructure negative test: a child failure must not reuse old traces.
 * This is not a kernel bug scenario or a replacement for the regmap target.
 */
#include <unistd.h>

void test_setup(void) { _exit(7); }
void test_thread1(void) {}
void test_thread2(void) {}
void test_end(void) {}
