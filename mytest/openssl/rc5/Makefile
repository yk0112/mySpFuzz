# コンパイラの定義
CC = clang-6.0

# コンパイルオプション
CFLAGS = -emit-llvm -g -c

# ソースファイル
SOURCE = rc5cfb64.c

# 出力ファイル
OUTPUT = rc5cfb64.bc

# デフォルトターゲット
all: $(OUTPUT)

# コンパイルコマンド
$(OUTPUT): $(SOURCE)
	$(CC) $(CFLAGS) $(SOURCE) -o $(OUTPUT)

# クリーンターゲット（生成ファイルの削除）
clean:
	rm -f $(OUTPUT)

# 再コンパイルターゲット
rebuild: clean all

