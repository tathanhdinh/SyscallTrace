module Main where

import qualified System.Environment as E
--import qualified Control.Monad as M
--import qualified Data.List as L
import ParseTrace
--import qualified Text.ParserCombinators.Parsec as Parsec

main :: IO ()
main = do 
  args <- E.getArgs
  case args of 
    (fileName : _) -> searchForLinearExtensionFromFile fileName
    --printGraphSelectedTraceFile fileName

    _ -> putStrLn "Please run as: this_program tracefile"

{-main :: IO ()
main = do 
  let rawLine = "1\ttest\targs\t"
  putStrLn $ show (parseRawLine rawLine)-}

{-parseLine :: String -> IO ()
parseLine aLine = do
  case Parsec.parse lineParser "error" aLine of 
    Left error -> putStrLn "Parsing error"
    Right fields -> M.mapM_ putStrLn fields

lineParser :: Parsec.GenParser Char state [String]
lineParser = do 
  field1 <- fieldParser
  Parsec.char ','
  field2 <- fieldParser
  return [field1,field2]

fieldParser :: Parsec.GenParser Char state String
fieldParser = Parsec.many (Parsec.noneOf ",")-}