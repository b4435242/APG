; ModuleID = '<string>'
source_filename = "<string>"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

define i1 @constraints(i256 %.1) {
entry:
  %.3 = and i256 %.1, -452312848583266388373324160190187140051835877600158453279131187530910662656
  %.4 = lshr i256 %.3, 248
  %node0 = trunc i256 %.4 to i8
  %node1 = icmp eq i8 %node0, 47
  %.5 = and i256 %.1, 450546001518488004043740862689444221536008393703282834321009581329618042880
  %.6 = lshr i256 %.5, 240
  %node2 = trunc i256 %.6 to i8
  %node3 = icmp ne i8 %node2, 0
  %node4 = and i1 %node1, %node3
  %.7 = and i256 %.1, 450546001518488004043740862689444221536008393703282834321009581329618042880
  %.8 = lshr i256 %.7, 240
  %node5 = trunc i256 %.8 to i8
  %node6 = icmp ne i8 %node5, 37
  %node7 = and i1 %node4, %node6
  %.9 = and i256 %.1, 450546001518488004043740862689444221536008393703282834321009581329618042880
  %.10 = lshr i256 %.9, 240
  %node8 = trunc i256 %.10 to i8
  %node9 = icmp ne i8 %node8, 47
  %node10 = and i1 %node7, %node9
  %.11 = and i256 %.1, 450546001518488004043740862689444221536008393703282834321009581329618042880
  %.12 = lshr i256 %.11, 240
  %node11 = trunc i256 %.12 to i8
  %node12 = icmp eq i8 %node11, 46
  %node13 = and i1 %node10, %node12
  %.13 = and i256 %.1, 1759945318431593765795862744880641490375032787903448571566443677068820480
  %.14 = lshr i256 %.13, 232
  %node14 = trunc i256 %.14 to i8
  %node15 = icmp ne i8 %node14, 0
  %node16 = and i1 %node13, %node15
  %.15 = and i256 %.1, 1759945318431593765795862744880641490375032787903448571566443677068820480
  %.16 = lshr i256 %.15, 232
  %node17 = trunc i256 %.16 to i8
  %node18 = icmp ne i8 %node17, 47
  %node19 = and i1 %node16, %node18
  %.17 = and i256 %.1, 1759945318431593765795862744880641490375032787903448571566443677068820480
  %.18 = lshr i256 %.17, 232
  %node20 = trunc i256 %.18 to i8
  %node21 = icmp eq i8 %node20, 46
  %node22 = and i1 %node19, %node21
  %.19 = and i256 %.1, 6874786400123413147640088847190005821777471827747845982681420613550080
  %.20 = lshr i256 %.19, 224
  %node23 = trunc i256 %.20 to i8
  %node24 = icmp eq i8 %node23, 0
  %node25 = and i1 %node22, %node24
  ret i1 %node25
}
