package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"mkasm/pkg/arm"
)

type inputSource struct {
	corpus         arm.XMLCorpus
	encodingIndex  string
	iformDirectory string
	description    string
}

func openInput(ctx context.Context, input string, stdin io.Reader) (inputSource, error) {
	if input == "" {
		return inputSource{}, &usageError{message: "INPUT cannot be empty"}
	}
	if input == "-" {
		corpus, err := arm.LoadTarXMLCorpus(stdin, "stdin")
		if err != nil {
			return inputSource{}, fmt.Errorf("read stdin corpus: %w", err)
		}
		return corpusInput(corpus), nil
	}
	if strings.HasPrefix(input, "https://") || strings.HasPrefix(input, "http://") {
		corpus, err := arm.OpenTarXMLCorpus(ctx, input)
		if err != nil {
			return inputSource{}, err
		}
		return corpusInput(corpus), nil
	}

	info, err := os.Stat(input)
	if err != nil {
		return inputSource{}, fmt.Errorf("open input %q: %w", input, err)
	}
	if info.IsDir() {
		return inputSource{
			encodingIndex:  filepath.Join(input, arm.ArchAArch64.SpecIndexFile()),
			iformDirectory: input,
			description:    input,
		}, nil
	}
	corpus, err := arm.OpenTarXMLCorpus(ctx, input)
	if err != nil {
		return inputSource{}, err
	}
	return corpusInput(corpus), nil
}

func corpusInput(corpus *arm.TarXMLCorpus) inputSource {
	return inputSource{
		corpus:        corpus,
		encodingIndex: arm.ArchAArch64.SpecIndexFile(),
		description:   corpus.Description(),
	}
}
