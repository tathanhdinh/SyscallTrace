module ParseTrace where

import qualified System.IO as I
import qualified Data.List as L
--import qualified System.Environment
import qualified Text.ParserCombinators.Parsec as Parsec
import qualified Control.Monad as M
import qualified Control.Monad.State as M
import qualified Control.Monad.Loops as M
--import qualified Control.Monad.LoopWhile as M
import qualified Text.Printf as P
import qualified Data.Graph.Inductive.Graph as G
import qualified Data.Graph.Inductive.Query.TransClos as G
import qualified Data.Graph.Inductive.Graphviz as G
import qualified Data.Random as R
import qualified Data.Random.Source.DevRandom as R
import qualified Data.Random.Extras as R

import Morphism

data RawSyscall = RawSyscall {
  sindex :: String, 
  sname :: String,
  sarguments :: String
}

instance Show RawSyscall where
  show rawSyscall = P.printf "%s %s %s" (sindex rawSyscall) (sname rawSyscall) (sarguments rawSyscall)

countLineTraceFile :: String -> IO Int
countLineTraceFile fileName = do 
  fileContent <- I.readFile fileName
  let fileLines = L.lines fileContent
  return $ L.length fileLines

printTraceFile :: String -> IO ()
printTraceFile fileName = do 
  fileContent <- I.readFile fileName
  let fileLines = L.lines fileContent 
  M.mapM_ putStrLn fileLines

printParsedTraceFile :: String -> IO () 
printParsedTraceFile fileName = do 
  fileContent <- I.readFile fileName 
  let fileLines = L.lines fileContent 
      rawSyscalls = map parseRawLine fileLines
      rawSyscallStrings = map show rawSyscalls
  M.mapM_ putStrLn rawSyscallStrings

parseRawLine :: String -> RawSyscall
parseRawLine rawLine = 
  case Parsec.parse rawLineParser "parsing error" rawLine of 
    Left _ -> RawSyscall { sindex = [], sname = [], sarguments = [] } 
    Right fields -> fields

rawLineParser :: Parsec.GenParser Char status RawSyscall
rawLineParser = do 
  syscallIndex <- Parsec.many (Parsec.noneOf "\t")
  _ <- Parsec.char '\t'
  syscallName <- Parsec.many (Parsec.noneOf "\t") 
  _ <- Parsec.char '\t'
  syscallArguments <- Parsec.many (Parsec.noneOf "\t")
  return RawSyscall { sindex = syscallIndex, sname = syscallName, sarguments = syscallArguments }

parseSyscall :: RawSyscall -> M.State ActiveObjects (Maybe Morphism)
parseSyscall rawSyscall = 
  case sname rawSyscall of 
    "NtCreateKey" -> parseNtCreateKey rawSyscall
    "NtSetValueKey" -> parseNtSetValueKey rawSyscall
    "NtQueryValueKey" -> parseNtQueryValueKey rawSyscall
    "NtOpenKey" -> parseNtOpenKey rawSyscall
    "NtClose" -> parseNtClose rawSyscall
    _ -> return Nothing

filterRawSyscalls :: [RawSyscall] -> M.State ActiveObjects [Morphism]
filterRawSyscalls rawSyscalls = 
  case rawSyscalls of 
    (rawSyscall : otherRawSyscalls) -> do 
      newMorphism <- parseSyscall rawSyscall
      case newMorphism of 
        Just morphism -> do 
          otherMorphisms <- filterRawSyscalls otherRawSyscalls
          return $ morphism : otherMorphisms
        Nothing -> filterRawSyscalls otherRawSyscalls
    _ -> return []

printSelectedTraceFile :: String -> IO ()
printSelectedTraceFile fileName = do 
  fileContent <- I.readFile fileName
  let rawLines = L.lines fileContent
      rawSyscalls = map parseRawLine rawLines
      selectedMorphisms = M.evalState (filterRawSyscalls rawSyscalls) []
      selectedMorphismStrings = map show selectedMorphisms
  M.mapM_ putStrLn selectedMorphismStrings 

parseGraphSyscall :: RawSyscall -> M.State ActiveOpenGraph () 
parseGraphSyscall rawSyscall = 
  case sname rawSyscall of 
    "NtCreateKey" -> parseGraphNtCreateKey rawSyscall
    "NtSetValueKey" -> parseGraphNtSetValueKey rawSyscall
    "NtQueryValueKey" -> parseGraphNtQueryValueKey rawSyscall 
    "NtOpenKey" -> parseGraphNtOpenKey rawSyscall 
    "NtClose" -> parseGraphNtClose rawSyscall
    _ -> return ()

parseGraphSyscall' ::RawSyscall -> M.State ActiveOpenGraph () 
parseGraphSyscall' rawSyscall = 
  case sname rawSyscall of 
    "NtCreateKey" -> parseGraphDataGenerator fNtCreateKeyParser rawSyscall
    "NtOpenKey" -> parseGraphDataGenerator fNtCreateKeyParser rawSyscall
    "NtCreateFile" -> parseGraphDataGenerator fNtCreateFileParser rawSyscall
    "NtOpenFile" -> parseGraphDataGenerator fNtCreateFileParser rawSyscall

    "NtSetValueKey" -> parseGraphDataModifier fNtSetValueKeyParser rawSyscall
    "NtQueryValueKey" -> parseGraphDataModifier fNtSetValueKeyParser rawSyscall
    "NtWriteFile" -> parseGraphDataModifier fNtWriteFileParser rawSyscall
    "NtReadFile" -> parseGraphDataModifier fNtWriteFileParser rawSyscall

    "NtClose" -> parseGraphDataAnnihilator fNtCloseParser rawSyscall

    _ -> return ()

filterGraphRawSyscalls :: [RawSyscall] -> M.State ActiveOpenGraph ()
filterGraphRawSyscalls = M.mapM_ parseGraphSyscall' 

printGraphSelectedTraceFile :: String -> IO ()
printGraphSelectedTraceFile fileName = do 
  --fileContent <- I.readFile fileName 
  --let rawLines = L.lines fileContent
  --    rawSyscalls = map parseRawLine rawLines
  --    inputNode = (0, "Input")
  --    outputNode = (1, "Output")
  --    initActiveOpenGraph = ActiveOpenGraph { graph = G.insNodes [inputNode,outputNode] G.empty, 
  --                                            input = fst inputNode, output = fst outputNode }
  --    finalActiveOpenGraph = M.execState (filterGraphRawSyscalls rawSyscalls) initActiveOpenGraph
  --putStrLn $ G.graphviz' (graph finalActiveOpenGraph)
  finalActiveOpenGraph <- constructGraph fileName
  putStrLn $ G.graphviz (graph finalActiveOpenGraph) "TraceOpenGraph" (8.3,11.7) (0,0) G.Portrait


{---------------------------------------------------------------------------------------------------------------------}
{-                                             generate random linear extensions                                     -}
{---------------------------------------------------------------------------------------------------------------------}
isConnected :: G.Node -> G.Node -> TransOpenGraph -> Bool
isConnected headNode tailNode transGraph = tailNode `L.elem` G.suc transGraph headNode

swapAt :: Int -> [G.Node] -> [G.Node]
swapAt index nodes = L.take index nodes ++ [nodes !! index + 1,nodes !! index] ++ L.drop (index + 1) nodes

randomLinearExtension :: TransOpenGraph -> [G.Node] -> IO [G.Node]
randomLinearExtension transGraph currentLE = do 
  let upperIndex = L.length currentLE - 2
  randomIndex <- R.runRVar (R.choice [0..upperIndex]) R.DevRandom 
  return $
    if isConnected (currentLE !! randomIndex) (currentLE !! (randomIndex + 1)) transGraph
    then []
    else swapAt randomIndex currentLE

constructGraph :: String -> IO ActiveOpenGraph
constructGraph fileName = do 
  fileContent <- I.readFile fileName
  let rawLines = L.lines fileContent
      rawSyscalls = map parseRawLine rawLines
      inputNode = (0, "Input")
      outputNode = (1, "Output")
      initActiveOpenGraph = ActiveOpenGraph { graph = G.insNodes [inputNode,outputNode] G.empty, 
                                              input = fst inputNode, output = fst outputNode }
      finalActiveOpenGraph = M.execState (filterGraphRawSyscalls rawSyscalls) initActiveOpenGraph
  return finalActiveOpenGraph

searchForLinearExtensionFromFile :: String -> IO ()
searchForLinearExtensionFromFile fileName = do 
  finalActiveOpenGraph <- constructGraph fileName
  let standardGraph = G.delNodes [0,1] (graph finalActiveOpenGraph)
  print (G.nodes standardGraph)
  let transGraph = G.trc standardGraph
  newLinExt <- M.iterateUntil (not . null) (randomLinearExtension transGraph (G.nodes standardGraph))
  --newLinExt <- randomLinearExtension transGraph (G.nodes standardGraph)
  print newLinExt


{---------------------------------------------------------------------------------------------------------------------}
{-                                                    parsing functions                                              -}
{---------------------------------------------------------------------------------------------------------------------}
{-error parsing morphism-}
errorMorphism :: String -> Morphism
errorMorphism syscallName = 
  Morphism { name = syscallName, source = "unknown", target = "unknown" }

{-parse NtCreateFile-}
fNtCreateFileParser :: Parsec.GenParser Char status String 
fNtCreateFileParser = do 
  _ <- Parsec.string "(FileHdl=>"
  Parsec.many (Parsec.noneOf ",")

parseNtCreateFile :: RawSyscall -> M.State ActiveObjects (Maybe Morphism)
parseNtCreateFile rawSyscall = 
  case Parsec.parse fNtCreateFileParser "parsing error" (sarguments rawSyscall) of 
    Left _ -> return Nothing
    Right object -> 
      if object == "0x00000000" 
      then return Nothing 
      else do 
        currentActiveObjects <- M.get
        M.put $ object : currentActiveObjects
        return $ Just Morphism { name = sname rawSyscall, source = "e", target = object }

parseGraphNtCreateFile :: RawSyscall -> M.State ActiveOpenGraph () 
parseGraphNtCreateFile rawSyscall = 
  case Parsec.parse fNtCreateFileParser "parsing error" (sarguments rawSyscall) of 
    Left _ -> return ()
    Right object -> 
      M.unless (object == "0x00000000") $ do
        currentActiveOpenGraph <- M.get
        let newId = L.length $ G.nodes (graph currentActiveOpenGraph)
            newNode = (newId, sname rawSyscall ++ "\n(" ++ show (newId - 1) ++ ")")
            newOpenGraph1 = G.insNode newNode (graph currentActiveOpenGraph)
            newEdge1 = (newId, output currentActiveOpenGraph, object)
            newOpenGraph2 = G.insEdge newEdge1 newOpenGraph1 
            newEdge2 = (input currentActiveOpenGraph, newId, "0x00000000")
            newOpenGraph3 = G.insEdge newEdge2 newOpenGraph2
        M.put ActiveOpenGraph { graph = newOpenGraph3, 
                                input = input currentActiveOpenGraph, 
                                output = output currentActiveOpenGraph }
        return ()

{-parse NtOpenFile-}
parseNtOpenFile :: RawSyscall -> M.State ActiveObjects (Maybe Morphism)
parseNtOpenFile = parseNtCreateFile

{-parse NtWriteFile-}
fNtWriteFileParser :: Parsec.GenParser Char status String
fNtWriteFileParser = do 
  _ <- Parsec.string "(FileHdl<=" 
  Parsec.many (Parsec.noneOf ",")

parseNtWriteFile :: RawSyscall -> M.State ActiveObjects (Maybe Morphism)
parseNtWriteFile rawSyscall = 
  case Parsec.parse fNtWriteFileParser "parsing error" (sarguments rawSyscall) of 
    Left _ -> return Nothing
    Right object -> do 
      currentActiveObjects <- M.get
      return $ 
        if object `L.elem` currentActiveObjects 
        then Just Morphism { name = sname rawSyscall, source = object, target = object }
        else Nothing

parseGraphNtWriteFile :: RawSyscall -> M.State ActiveOpenGraph ()
parseGraphNtWriteFile = parseGraphNtSetValueKey 

{-parse NtReadFile-} 
parseNtReadFile :: RawSyscall -> M.State ActiveObjects (Maybe Morphism)
parseNtReadFile = parseNtWriteFile

parseGraphNtReadFile :: RawSyscall -> M.State ActiveOpenGraph ()
parseGraphNtReadFile = parseGraphNtWriteFile

{-parse NtClose-}
fNtCloseParser :: Parsec.GenParser Char status String
fNtCloseParser = do 
  _ <- Parsec.string "(Hdl<=" 
  Parsec.many (Parsec.noneOf ",)")

{-linear parsing-}
parseNtClose :: RawSyscall -> M.State ActiveObjects (Maybe Morphism)
parseNtClose rawSyscall = 
  case Parsec.parse fNtCloseParser "parsing error" (sarguments rawSyscall) of 
    Left _ -> return Nothing
    Right object -> do 
      currentActiveObjects <- M.get 
      if object `L.elem` currentActiveObjects
      then do 
        let newActiveObjects = L.filter ( /= object) currentActiveObjects 
        M.put newActiveObjects
        return $ Just Morphism { name = sname rawSyscall, source = object, target = "e" }
      else return Nothing

{-graphical parsing-}
parseGraphNtClose :: RawSyscall -> M.State ActiveOpenGraph ()
parseGraphNtClose rawSyscall = 
  case Parsec.parse fNtCloseParser "parsing error" (sarguments rawSyscall) of 
    Left _ -> return ()
    Right object -> do 
      currentActiveOpenGraph <- M.get
      let openLEdges = G.inn (graph currentActiveOpenGraph) (output currentActiveOpenGraph)
      case L.find (\(_,_,x) -> x == object) openLEdges of 
        Nothing -> return ()
        Just (pre, _, _) -> do
        let newId = L.length $ G.nodes (graph currentActiveOpenGraph)
            newNode = (newId, sname rawSyscall ++ "\n(" ++ show (newId - 1) ++ ")") 
            newEdge1 = (pre, newId, object)
            newEdge2 = (newId, output currentActiveOpenGraph, "0x00000000")
            exisingEdge = (pre, output currentActiveOpenGraph, object)
            newOpenGraph1 = G.insNode newNode (graph currentActiveOpenGraph) 
            newOpenGraph2 = G.insEdges [newEdge1,newEdge2] newOpenGraph1
            newOpenGraph3 = G.delLEdge exisingEdge newOpenGraph2
        M.put ActiveOpenGraph { graph = newOpenGraph3, 
                                input = input currentActiveOpenGraph, 
                                output = output currentActiveOpenGraph }
        return ()

{-parse NtCreateKey-}
fNtCreateKeyParser :: Parsec.GenParser Char status String
fNtCreateKeyParser = do 
  _ <- Parsec.string "(KeyHdl=>" 
  Parsec.many (Parsec.noneOf ",")

parseNtCreateKey :: RawSyscall -> M.State ActiveObjects (Maybe Morphism)
parseNtCreateKey rawSyscall = 
  case Parsec.parse fNtCreateKeyParser "parsing error" (sarguments rawSyscall) of 
    Left _ -> return Nothing
    Right object -> 
      if object == "0x00000000" 
      then return Nothing
      else do 
        currentActiveObjects <- M.get
        M.put $ object : currentActiveObjects
        return $ Just Morphism { name = sname rawSyscall, source = "e", target = object }

{-parse NtCreateKey-}
parseGraphNtCreateKey :: RawSyscall -> M.State ActiveOpenGraph ()
parseGraphNtCreateKey rawSyscall = 
  case Parsec.parse fNtCreateKeyParser "parsing error" (sarguments rawSyscall) of 
    Left _ -> return ()
    Right object -> M.unless (object == "0x00000000") $ do
      currentActiveOpenGraph <- M.get
      let newId = L.length $ G.nodes (graph currentActiveOpenGraph)
          newNode = (newId, sname rawSyscall ++ "\n(" ++ show (newId - 1) ++ ")")
          newOpenGraph1 = G.insNode newNode (graph currentActiveOpenGraph)
          newEdge1 = (newId, output currentActiveOpenGraph, object)
          newOpenGraph2 = G.insEdge newEdge1 newOpenGraph1 
          newEdge2 = (input currentActiveOpenGraph, newId, "0x00000000")
          newOpenGraph3 = G.insEdge newEdge2 newOpenGraph2
      M.put ActiveOpenGraph { graph = newOpenGraph3, 
                              input = input currentActiveOpenGraph, 
                              output = output currentActiveOpenGraph }
      return ()

parseNtOpenKey :: RawSyscall -> M.State ActiveObjects (Maybe Morphism)
parseNtOpenKey = parseNtCreateKey

{-parse NtOpenKey-}
parseGraphNtOpenKey :: RawSyscall -> M.State ActiveOpenGraph ()
parseGraphNtOpenKey = parseGraphNtCreateKey 

{-parse NtSetValueKey-}
fNtSetValueKeyParser :: Parsec.GenParser Char status String 
fNtSetValueKeyParser = do 
  _ <- Parsec.string "(KeyHdl<=" 
  Parsec.many (Parsec.noneOf ",")

parseNtSetValueKey :: RawSyscall -> M.State ActiveObjects (Maybe Morphism)
parseNtSetValueKey rawSyscall = 
  case Parsec.parse fNtSetValueKeyParser "parsing error" (sarguments rawSyscall) of 
    Left _ -> return Nothing
    Right object -> do 
      currentActiveObjects <- M.get
      return $ 
        if object `L.elem` currentActiveObjects 
        then Just Morphism { name = sname rawSyscall, source = object, target = object }
        else Nothing

parseGraphNtSetValueKey :: RawSyscall -> M.State ActiveOpenGraph ()
parseGraphNtSetValueKey rawSyscall = 
  case Parsec.parse fNtSetValueKeyParser "parsing error" (sarguments rawSyscall) of 
    Left _ -> return ()
    Right object -> do 
      currentActiveOpenGraph <- M.get
      let openLEdges = G.inn (graph currentActiveOpenGraph) (output currentActiveOpenGraph)
      case L.find (\(_,_,x) -> x == object) openLEdges of 
        Nothing -> return ()
        Just (pre, _, _) -> do 
        let newId = L.length $ G.nodes (graph currentActiveOpenGraph)
            newNode = (newId, sname rawSyscall ++ "\n(" ++ show (newId - 1) ++ ")") 
            newEdge1 = (pre, newId, object)
            newEdge2 = (newId, output currentActiveOpenGraph, object) 
            exisingEdge = (pre, output currentActiveOpenGraph, object)
            newOpenGraph1 = G.insNode newNode (graph currentActiveOpenGraph) 
            newOpenGraph2 = G.insEdges [newEdge1,newEdge2] newOpenGraph1
            newOpenGraph3 = G.delLEdge exisingEdge newOpenGraph2
        M.put ActiveOpenGraph { graph = newOpenGraph3, 
                                input = input currentActiveOpenGraph, 
                                output = output currentActiveOpenGraph }
        return ()


parseNtQueryValueKey :: RawSyscall -> M.State ActiveObjects (Maybe Morphism)
parseNtQueryValueKey = parseNtSetValueKey

parseGraphNtQueryValueKey :: RawSyscall -> M.State ActiveOpenGraph ()
parseGraphNtQueryValueKey = parseGraphNtSetValueKey

parseGraphDataModifier :: Parsec.Parser String -> RawSyscall -> M.State ActiveOpenGraph ()
parseGraphDataModifier syscallParser rawSyscall = 
  case Parsec.parse syscallParser "parsing error" (sarguments rawSyscall) of 
    Left _ -> return ()
    Right object -> do 
      currentActiveOpenGraph <- M.get
      let openLEdges = G.inn (graph currentActiveOpenGraph) (output currentActiveOpenGraph)
      case L.find (\(_,_,x) -> x == object) openLEdges of 
        Nothing -> return ()
        Just (pre, _, _) -> do 
        let newId = L.length $ G.nodes (graph currentActiveOpenGraph)
            newNode = (newId, sname rawSyscall ++ "\n(" ++ show (newId - 1) ++ ")") 
            newEdge1 = (pre, newId, object)
            newEdge2 = (newId, output currentActiveOpenGraph, object) 
            exisingEdge = (pre, output currentActiveOpenGraph, object)
            newOpenGraph1 = G.insNode newNode (graph currentActiveOpenGraph) 
            newOpenGraph2 = G.insEdges [newEdge1,newEdge2] newOpenGraph1
            newOpenGraph3 = G.delLEdge exisingEdge newOpenGraph2
        M.put ActiveOpenGraph { graph = newOpenGraph3, 
                                input = input currentActiveOpenGraph, 
                                output = output currentActiveOpenGraph }
        return () 


parseGraphDataGenerator :: Parsec.Parser String -> RawSyscall -> M.State ActiveOpenGraph () 
parseGraphDataGenerator syscallParser rawSyscall = 
  case Parsec.parse syscallParser "parsing error" (sarguments rawSyscall) of 
    Left _ -> return () 
    Right object -> M.unless (object == "0x00000000") $ do
      currentActiveOpenGraph <- M.get
      let newId = L.length $ G.nodes (graph currentActiveOpenGraph)
          newNode = (newId, sname rawSyscall ++ "\n(" ++ show (newId - 1) ++ ")")
          newOpenGraph1 = G.insNode newNode (graph currentActiveOpenGraph)
          newEdge1 = (newId, output currentActiveOpenGraph, object)
          newOpenGraph2 = G.insEdge newEdge1 newOpenGraph1 
          newEdge2 = (input currentActiveOpenGraph, newId, "0x00000000")
          newOpenGraph3 = G.insEdge newEdge2 newOpenGraph2
      M.put ActiveOpenGraph { graph = newOpenGraph3, 
                              input = input currentActiveOpenGraph, 
                              output = output currentActiveOpenGraph }
      return ()

parseGraphDataAnnihilator :: Parsec.Parser String -> RawSyscall -> M.State ActiveOpenGraph () 
parseGraphDataAnnihilator syscallParser rawSyscall = 
  case Parsec.parse syscallParser "parsing error" (sarguments rawSyscall) of 
    Left _ -> return () 
    Right object -> do 
      currentActiveOpenGraph <- M.get
      let openLEdges = G.inn (graph currentActiveOpenGraph) (output currentActiveOpenGraph)
      case L.find (\(_,_,x) -> x == object) openLEdges of 
        Nothing -> return ()
        Just (pre, _, _) -> do
        let newId = L.length $ G.nodes (graph currentActiveOpenGraph)
            newNode = (newId, sname rawSyscall ++ "\n(" ++ show (newId - 1) ++ ")") 
            newEdge1 = (pre, newId, object)
            newEdge2 = (newId, output currentActiveOpenGraph, "0x00000000")
            exisingEdge = (pre, output currentActiveOpenGraph, object)
            newOpenGraph1 = G.insNode newNode (graph currentActiveOpenGraph) 
            newOpenGraph2 = G.insEdges [newEdge1,newEdge2] newOpenGraph1
            newOpenGraph3 = G.delLEdge exisingEdge newOpenGraph2
        M.put ActiveOpenGraph { graph = newOpenGraph3, 
                                input = input currentActiveOpenGraph, 
                                output = output currentActiveOpenGraph }
        return ()