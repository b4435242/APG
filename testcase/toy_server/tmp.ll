; ModuleID = '<string>'
source_filename = "<string>"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

define i1 @constraints(i32 %.1) {
entry:
  %.3 = shl i32 %.1, 24
  %.4 = shl i32 255, 24
  %.5 = and i32 %.3, %.4
  %.6 = lshr i32 %.1, 24
  %.7 = shl i32 255, 0
  %.8 = and i32 %.6, %.7
  %.9 = or i32 %.5, %.8
  %node0 = or i32 %.9, 0
  %.10 = shl i32 %.1, 8
  %.11 = shl i32 255, 16
  %.12 = and i32 %.10, %.11
  %.13 = lshr i32 %.1, 8
  %.14 = shl i32 255, 8
  %.15 = and i32 %.13, %.14
  %.16 = or i32 %.12, %.15
  %node0.1 = or i32 %.16, %node0
  %node1 = icmp sle i32 %node0.1, 0
  ret i1 %node1
}
